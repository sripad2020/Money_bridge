package emulator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
	"pstcopay/sdk/wallet"
)

// SIMApplet emulates a SIM or embedded secure element applet: the key, PIN
// retry counter, balance, counter and chain head all live inside the applet,
// so nothing the phone's storage holds can roll them back.
type SIMApplet struct {
	mu       sync.Mutex
	root     *Root
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	pin      string
	retries  int
	unlocked bool

	deviceID   uint64
	cert, ca   []byte
	certLimit  int64
	reserveID  uint64
	balance    int64
	next       uint32
	head       [offline.HashSize]byte
	expiry     uint32
	perPayment int64
}

// NewSIMApplet personalises an applet with a PIN.
func NewSIMApplet(root *Root, pin string) (*SIMApplet, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SIMApplet{root: root, pub: pub, priv: priv, pin: pin, retries: 3, next: 1}, nil
}

func (s *SIMApplet) Info() wallet.ElementInfo {
	return wallet.ElementInfo{Kind: "sim-applet", Alg: offline.AlgEd25519}
}

func (s *SIMApplet) PublicKey() ([]byte, error) { return append([]byte(nil), s.pub...), nil }

// Attest returns the applet's certificate chain, issued by the SIM CA.
func (s *SIMApplet) Attest([]byte) (api.Attestation, error) {
	der, err := s.root.issue(s.pub, nil)
	if err != nil {
		return api.Attestation{}, err
	}
	return api.Attestation{Format: "sim-x509", Chain: [][]byte{der}}, nil
}

func (s *SIMApplet) SignAuth(msg []byte) ([]byte, error) {
	if !bytes.HasPrefix(msg, []byte(api.RequestTag)) && !bytes.HasPrefix(msg, []byte(api.RegisterTag)) {
		return nil, wallet.ErrRefusedToSign
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.unlocked {
		return nil, wallet.ErrLocked
	}
	return ed25519.Sign(s.priv, msg), nil
}

// Unlock checks the PIN inside the applet; three wrong PINs block it.
func (s *SIMApplet) Unlock(pin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retries == 0 {
		return wallet.ErrLockedOut
	}
	if pin != s.pin {
		s.retries--
		return wallet.ErrWrongPIN
	}
	s.retries, s.unlocked = 3, true
	return nil
}

func (s *SIMApplet) Lock() {
	s.mu.Lock()
	s.unlocked = false
	s.mu.Unlock()
}

func (s *SIMApplet) Provision(certRaw, caPub []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, _, err := offline.ParseDeviceCert(certRaw)
	if err != nil {
		return err
	}
	if err := c.Verify(caPub, time.Now()); err != nil {
		return err
	}
	if !bytes.Equal(c.PublicKey, s.pub) {
		return errors.New("sim: certificate is for another key")
	}
	s.deviceID, s.cert, s.ca, s.certLimit = c.DeviceID, certRaw, caPub, c.PerPaymentLimit
	return nil
}

func (s *SIMApplet) LoadReserve(raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := offline.ParseReserve(raw)
	if err != nil {
		return err
	}
	if err := r.Verify(s.ca); err != nil {
		return err
	}
	if r.DeviceID != s.deviceID {
		return errors.New("sim: reserve for another device")
	}
	if r.ReserveID == s.reserveID {
		return nil
	}
	if r.CounterStart != s.next {
		return fmt.Errorf("sim: reserve starts at %d, applet at %d", r.CounterStart, s.next)
	}
	s.reserveID, s.balance, s.expiry = r.ReserveID, r.AmountPaise, r.Expiry
	s.perPayment, s.head = min(r.PerPaymentLimit, s.certLimit), offline.ReserveGenesis(raw)
	return nil
}

func (s *SIMApplet) Pay(payee uint64, amount int64, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.unlocked:
		return nil, wallet.ErrLocked
	case s.reserveID == 0:
		return nil, wallet.ErrNoReserve
	case uint32(now.Unix()) >= s.expiry:
		return nil, wallet.ErrReserveExpired
	case amount > s.perPayment:
		return nil, wallet.ErrOverLimit
	case amount > s.balance:
		return nil, wallet.ErrInsufficient
	case s.next == math.MaxUint32:
		return nil, errors.New("sim: counter exhausted")
	}
	r := &offline.Record{Version: offline.RecordV1, DeviceID: s.deviceID, Counter: s.next, AmountPaise: amount,
		PayeeID: payee, Timestamp: uint32(now.Unix()), Expiry: s.expiry, PrevHash: s.head}
	signed, err := r.SignedBytes()
	if err != nil {
		return nil, err
	}
	raw := append(signed, ed25519.Sign(s.priv, offline.SigningMessage(signed))...)
	s.balance -= amount
	s.next++
	s.head = offline.RecordHash(raw)
	return raw, nil
}

func (s *SIMApplet) State() (wallet.ElementState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return wallet.ElementState{Locked: !s.unlocked, DeviceID: s.deviceID, Provisioned: s.deviceID != 0,
		ReserveID: s.reserveID, BalancePaise: s.balance, NextCounter: s.next, ChainHead: s.head,
		Expiry: s.expiry, PerPaymentLimit: s.perPayment}, nil
}

var _ wallet.Element = (*SIMApplet)(nil)
