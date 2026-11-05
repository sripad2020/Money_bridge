package wallet

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
)

const (
	elementFile  = "element.sealed"
	attemptsFile = "element.attempts"
	lockoutAfter = 5
	wipeAfter    = 10
)

// SealedElement is a secure element for phones. With a hardware KeyStore the
// signing key stays in StrongBox, TEE or the Secure Enclave; without one it
// generates an Ed25519 key in software. Either way the balance, counter and
// chain head are sealed with AES-256-GCM under a data key protected by an
// Argon2id key from the PIN (and by the hardware Sealer when available),
// written atomically before any record is released.
//
// A software element cannot stop someone who copies and later restores its
// files; the server detects such a rollback as two records with one counter,
// freezes the device, and the reserve caps the loss. That is why software
// elements get lower limits.
type SealedElement struct {
	dir string
	ks  KeyStore
	kdf KDF
	now func() time.Time

	mu    sync.Mutex
	dek   []byte
	seed  []byte
	state *sealedState
}

type sealedFile struct {
	Version    int    `json:"version"`
	Kind       string `json:"kind"`
	KDF        KDF    `json:"kdf"`
	Salt       []byte `json:"salt"`
	WrappedDEK []byte `json:"wrapped_dek"`
	HWSealed   bool   `json:"hw_sealed"`
	State      []byte `json:"state"`
}

type sealedState struct {
	Alg             offline.Alg `json:"alg"`
	Seed            []byte      `json:"seed,omitempty"` // software key only
	PublicKey       []byte      `json:"public_key"`
	DeviceID        uint64      `json:"device_id"`
	Cert            []byte      `json:"cert,omitempty"`
	CAPublicKey     []byte      `json:"ca_public_key,omitempty"`
	CertLimit       int64       `json:"cert_limit"`
	Reserve         []byte      `json:"reserve,omitempty"`
	ReserveID       uint64      `json:"reserve_id"`
	Balance         int64       `json:"balance"`
	NextCounter     uint32      `json:"next_counter"`
	ChainHead       []byte      `json:"chain_head"`
	Expiry          uint32      `json:"expiry"`
	PerPaymentLimit int64       `json:"per_payment_limit"`
	Generation      uint64      `json:"generation"`
}

type attempts struct {
	Failures    int   `json:"failures"`
	LockedUntil int64 `json:"locked_until"`
}

// ElementOptions tunes a sealed element.
type ElementOptions struct {
	KDF KDF
	Now func() time.Time
}

func (o *ElementOptions) defaults() {
	if o.KDF == (KDF{}) {
		o.KDF = DefaultKDF
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// CreateSealedElement initialises a new element in dir. Pass ks = nil on
// devices without secure hardware.
func CreateSealedElement(dir, pin string, ks KeyStore, o ElementOptions) (*SealedElement, error) {
	o.defaults()
	if !validPIN(pin) {
		return nil, ErrWeakPIN
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, elementFile)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("wallet: element already exists in %s", dir)
	}
	e := &SealedElement{dir: dir, ks: ks, kdf: o.KDF, now: o.Now}
	st := &sealedState{NextCounter: 1, ChainHead: make([]byte, offline.HashSize)}
	if ks == nil {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		st.Alg, st.Seed, st.PublicKey = offline.AlgEd25519, priv.Seed(), pub
	} else {
		pub, err := ks.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("wallet: hardware key: %w", err)
		}
		st.Alg, st.PublicKey = ks.Alg(), pub
	}
	salt := randomBytes(16)
	dek := randomBytes(32)
	kek := o.KDF.derive(pin, salt)
	defer zero(kek)
	wrapped, err := seal(kek, dek, []byte("pstco-dek"))
	if err != nil {
		return nil, err
	}
	f := &sealedFile{Version: 1, Kind: e.Info().Kind, KDF: o.KDF, Salt: salt}
	if s, ok := ks.(Sealer); ok && ks != nil {
		if wrapped, err = s.Seal(wrapped); err != nil {
			return nil, fmt.Errorf("wallet: hardware seal: %w", err)
		}
		f.HWSealed = true
	}
	f.WrappedDEK = wrapped
	e.dek, e.state = dek, st
	if ks == nil {
		e.seed = st.Seed
	}
	if err := e.persistLocked(f); err != nil {
		return nil, err
	}
	return e, nil
}

// OpenSealedElement opens an existing element (locked).
func OpenSealedElement(dir string, ks KeyStore, o ElementOptions) (*SealedElement, error) {
	o.defaults()
	if _, err := os.Stat(filepath.Join(dir, elementFile)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, aerr := os.Stat(filepath.Join(dir, attemptsFile)); aerr == nil {
				return nil, ErrWiped
			}
		}
		return nil, err
	}
	return &SealedElement{dir: dir, ks: ks, kdf: o.KDF, now: o.Now}, nil
}

// Info implements Element.
func (e *SealedElement) Info() ElementInfo {
	if e.ks == nil {
		return ElementInfo{Kind: "software", Alg: offline.AlgEd25519}
	}
	return ElementInfo{Kind: e.ks.Kind(), Alg: e.ks.Alg()}
}

func (e *SealedElement) readFile() (*sealedFile, error) {
	b, err := os.ReadFile(filepath.Join(e.dir, elementFile))
	if err != nil {
		return nil, err
	}
	var f sealedFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("wallet: element file corrupt: %w", err)
	}
	return &f, nil
}

func (e *SealedElement) readAttempts() attempts {
	var a attempts
	if b, err := os.ReadFile(filepath.Join(e.dir, attemptsFile)); err == nil {
		_ = json.Unmarshal(b, &a)
	}
	return a
}

func (e *SealedElement) writeAttempts(a attempts) error {
	b, _ := json.Marshal(a)
	return writeFileAtomic(filepath.Join(e.dir, attemptsFile), b)
}

// Unlock implements Element. Wrong PINs lock the element out with growing
// delays after 5 attempts and wipe it after 10.
func (e *SealedElement) Unlock(pin string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dek != nil {
		return nil
	}
	a := e.readAttempts()
	now := e.now()
	if a.LockedUntil > now.Unix() {
		return ErrLockedOut
	}
	f, err := e.readFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrWiped
		}
		return err
	}
	wrapped := f.WrappedDEK
	if f.HWSealed {
		s, ok := e.ks.(Sealer)
		if !ok {
			return errors.New("wallet: element was sealed by hardware that is not available")
		}
		if wrapped, err = s.Unseal(wrapped); err != nil {
			return fmt.Errorf("wallet: hardware unseal: %w", err)
		}
	}
	kek := f.KDF.derive(pin, f.Salt)
	defer zero(kek)
	dek, err := open(kek, wrapped, []byte("pstco-dek"))
	if err != nil {
		a.Failures++
		if a.Failures >= wipeAfter {
			_ = os.Remove(filepath.Join(e.dir, elementFile))
			_ = e.writeAttempts(a)
			return ErrWiped
		}
		if a.Failures >= lockoutAfter {
			delay := time.Duration(30*math.Pow(2, float64(a.Failures-lockoutAfter))) * time.Second
			a.LockedUntil = now.Add(delay).Unix()
		}
		_ = e.writeAttempts(a)
		return ErrWrongPIN
	}
	plain, err := open(dek, f.State, []byte("pstco-state"))
	if err != nil {
		zero(dek)
		return fmt.Errorf("wallet: element state corrupt: %w", err)
	}
	var st sealedState
	if err := json.Unmarshal(plain, &st); err != nil {
		zero(dek)
		return err
	}
	zero(plain)
	if a.Failures != 0 {
		_ = e.writeAttempts(attempts{})
	}
	e.dek, e.state = dek, &st
	if e.ks == nil {
		e.seed = st.Seed
	}
	return nil
}

// Lock implements Element and wipes key material from memory.
func (e *SealedElement) Lock() {
	e.mu.Lock()
	defer e.mu.Unlock()
	zero(e.dek)
	if e.state != nil {
		zero(e.state.Seed)
	}
	e.dek, e.seed, e.state = nil, nil, nil
}

// persistLocked seals the state and writes the element file atomically.
func (e *SealedElement) persistLocked(f *sealedFile) error {
	if f == nil {
		var err error
		if f, err = e.readFile(); err != nil {
			return err
		}
	}
	plain, err := json.Marshal(e.state)
	if err != nil {
		return err
	}
	defer zero(plain)
	if f.State, err = seal(e.dek, plain, []byte("pstco-state")); err != nil {
		return err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(e.dir, elementFile), b)
}

// PublicKey implements Element.
func (e *SealedElement) PublicKey() ([]byte, error) {
	if e.ks != nil {
		return e.ks.PublicKey()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == nil {
		return nil, ErrLocked
	}
	return append([]byte(nil), e.state.PublicKey...), nil
}

// Attest implements Element.
func (e *SealedElement) Attest(challenge []byte) (api.Attestation, error) {
	if e.ks == nil {
		return api.Attestation{Format: "none"}, nil
	}
	return e.ks.Attest(challenge)
}

func (e *SealedElement) signLocked(msg []byte) ([]byte, error) {
	if e.ks != nil {
		sig, err := e.ks.Sign(msg)
		if err != nil {
			return nil, err
		}
		if len(sig) != 64 {
			return nil, fmt.Errorf("wallet: hardware returned a %d-byte signature, want 64", len(sig))
		}
		return sig, nil
	}
	if e.seed == nil {
		return nil, ErrLocked
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(e.seed), msg), nil
}

// SignAuth implements Element.
func (e *SealedElement) SignAuth(msg []byte) ([]byte, error) {
	if !bytes.HasPrefix(msg, []byte(api.RequestTag)) && !bytes.HasPrefix(msg, []byte(api.RegisterTag)) {
		return nil, ErrRefusedToSign
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == nil {
		return nil, ErrLocked
	}
	return e.signLocked(msg)
}

// Provision implements Element.
func (e *SealedElement) Provision(certRaw, caPub []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == nil {
		return ErrLocked
	}
	c, n, err := offline.ParseDeviceCert(certRaw)
	if err != nil || n != len(certRaw) {
		return fmt.Errorf("wallet: certificate: %v", err)
	}
	if err := c.Verify(caPub, e.now()); err != nil {
		return err
	}
	pub := e.state.PublicKey
	if e.ks != nil { // hardware keys may be re-created at attestation time
		if pub, err = e.ks.PublicKey(); err != nil {
			return err
		}
	}
	if !bytes.Equal(c.PublicKey, pub) || c.Alg != e.state.Alg {
		return errors.New("wallet: certificate is for another key")
	}
	e.state.PublicKey = pub
	if e.state.DeviceID != 0 && e.state.DeviceID != c.DeviceID {
		return errors.New("wallet: element already provisioned for another device id")
	}
	e.state.DeviceID, e.state.Cert, e.state.CAPublicKey, e.state.CertLimit = c.DeviceID, certRaw, caPub, c.PerPaymentLimit
	e.state.Generation++
	return e.persistLocked(nil)
}

// LoadReserve implements Element.
func (e *SealedElement) LoadReserve(raw []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == nil {
		return ErrLocked
	}
	if e.state.DeviceID == 0 {
		return ErrNotProvisioned
	}
	r, err := offline.ParseReserve(raw)
	if err != nil {
		return err
	}
	if err := r.Verify(e.state.CAPublicKey); err != nil {
		return err
	}
	if r.DeviceID != e.state.DeviceID {
		return errors.New("wallet: reserve is for another device")
	}
	if r.ReserveID == e.state.ReserveID {
		return nil // already loaded (retry)
	}
	if r.CounterStart != e.state.NextCounter {
		return fmt.Errorf("wallet: reserve starts at counter %d but the element is at %d; sync first", r.CounterStart, e.state.NextCounter)
	}
	g := offline.ReserveGenesis(raw)
	e.state.Reserve, e.state.ReserveID, e.state.Balance = raw, r.ReserveID, r.AmountPaise
	e.state.Expiry, e.state.PerPaymentLimit, e.state.ChainHead = r.Expiry, min(r.PerPaymentLimit, e.state.CertLimit), g[:]
	e.state.Generation++
	return e.persistLocked(nil)
}

// Pay implements Element.
func (e *SealedElement) Pay(payee uint64, amount int64, now time.Time) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.state
	switch {
	case st == nil:
		return nil, ErrLocked
	case st.DeviceID == 0:
		return nil, ErrNotProvisioned
	case st.ReserveID == 0:
		return nil, ErrNoReserve
	case uint32(now.Unix()) >= st.Expiry:
		return nil, ErrReserveExpired
	case amount <= 0:
		return nil, offline.ErrAmount
	case amount > st.PerPaymentLimit:
		return nil, ErrOverLimit
	case amount > st.Balance:
		return nil, ErrInsufficient
	case st.NextCounter == math.MaxUint32:
		return nil, errors.New("wallet: counter exhausted")
	}
	r := &offline.Record{Version: offline.RecordV1, DeviceID: st.DeviceID, Counter: st.NextCounter,
		AmountPaise: amount, PayeeID: payee, Timestamp: uint32(now.Unix()), Expiry: st.Expiry}
	copy(r.PrevHash[:], st.ChainHead)
	signed, err := r.SignedBytes()
	if err != nil {
		return nil, err
	}
	sig, err := e.signLocked(offline.SigningMessage(signed))
	if err != nil {
		return nil, err
	}
	raw := append(signed, sig...)
	prev := *st
	h := offline.RecordHash(raw)
	st.Balance -= amount
	st.NextCounter++
	st.ChainHead = h[:]
	st.Generation++
	// Persist before releasing the record: if this fails, the record is
	// discarded and the balance is unchanged.
	if err := e.persistLocked(nil); err != nil {
		*st = prev
		return nil, fmt.Errorf("wallet: could not record payment: %w", err)
	}
	return raw, nil
}

// State implements Element.
func (e *SealedElement) State() (ElementState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == nil {
		return ElementState{Locked: true}, nil
	}
	st := e.state
	out := ElementState{DeviceID: st.DeviceID, Provisioned: st.DeviceID != 0, ReserveID: st.ReserveID,
		BalancePaise: st.Balance, NextCounter: st.NextCounter, Expiry: st.Expiry, PerPaymentLimit: st.PerPaymentLimit}
	copy(out.ChainHead[:], st.ChainHead)
	return out, nil
}

// isSoftware reports whether the element has no secure hardware.
func isSoftware(kind string) bool { return kind == "" || strings.EqualFold(kind, "software") }
