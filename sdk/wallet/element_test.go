package wallet_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pstcopay/sdk/attest"
	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
	"pstcopay/sdk/wallet"
	"pstcopay/sdk/wallet/emulator"
)

const pin = "246810"

type fixture struct {
	caPub  ed25519.PublicKey
	caPriv ed25519.PrivateKey
}

func newFixture() *fixture {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &fixture{caPub: pub, caPriv: priv}
}

func (f *fixture) sign(m []byte) []byte { return ed25519.Sign(f.caPriv, m) }

// provision issues a certificate and a reserve to an element.
func (f *fixture) provision(t *testing.T, el wallet.Element, amount int64) uint64 {
	t.Helper()
	pub, err := el.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &offline.DeviceCert{Version: offline.CertV1, DeviceID: 77, OwnerPayee: 1, Alg: el.Info().Alg,
		Trust: offline.TrustSoftware, PerPaymentLimit: 500_00, MaxReserve: 2000_00, IssuedAt: uint32(now.Unix()),
		ExpiresAt: uint32(now.Add(time.Hour).Unix()), PublicKey: pub}
	if err := cert.Sign(f.sign); err != nil {
		t.Fatal(err)
	}
	raw, _ := cert.Marshal()
	if err := el.Provision(raw, f.caPub); err != nil {
		t.Fatal(err)
	}
	st, _ := el.State()
	r := &offline.Reserve{Version: offline.ReserveV1, ReserveID: 5, DeviceID: 77, AmountPaise: amount,
		CounterStart: st.NextCounter, PerPaymentLimit: 500_00, Expiry: uint32(now.Add(time.Hour).Unix()),
		IssuedAt: uint32(now.Unix())}
	if err := r.Sign(f.sign); err != nil {
		t.Fatal(err)
	}
	rr, _ := r.Marshal()
	if err := el.LoadReserve(rr); err != nil {
		t.Fatal(err)
	}
	return 77
}

func TestSealedElementPaysChainsAndPersists(t *testing.T) {
	f := newFixture()
	dir := t.TempDir()
	el, err := wallet.CreateSealedElement(dir, pin, nil, wallet.ElementOptions{KDF: wallet.TestKDF})
	if err != nil {
		t.Fatal(err)
	}
	f.provision(t, el, 1000_00)
	r1, err := el.Pay(9, 100_00, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := el.Pay(9, 50_00, time.Now())
	rec2, _ := offline.ParseRecord(r2)
	if rec2.Counter != 2 || rec2.PrevHash != offline.RecordHash(r1) {
		t.Fatal("second record does not link to the first")
	}
	pub, _ := el.PublicKey()
	if offline.VerifyRecordSignature(r2, offline.AlgEd25519, pub) != nil {
		t.Fatal("record signature invalid")
	}
	if _, err := el.Pay(9, 600_00, time.Now()); !errors.Is(err, wallet.ErrOverLimit) {
		t.Fatalf("over limit: %v", err)
	}
	el.Lock()
	if _, err := el.Pay(9, 1, time.Now()); !errors.Is(err, wallet.ErrLocked) {
		t.Fatalf("locked pay: %v", err)
	}
	// Reopen from disk: the deduction and counter survived.
	el2, _ := wallet.OpenSealedElement(dir, nil, wallet.ElementOptions{KDF: wallet.TestKDF})
	if err := el2.Unlock(pin); err != nil {
		t.Fatal(err)
	}
	st, _ := el2.State()
	if st.BalancePaise != 850_00 || st.NextCounter != 3 {
		t.Fatalf("persisted state %+v", st)
	}
}

func TestElementRefusesToSignArbitraryMessages(t *testing.T) {
	el, _ := wallet.CreateSealedElement(t.TempDir(), pin, nil, wallet.ElementOptions{KDF: wallet.TestKDF})
	// A request signature must never be usable as a payment record signature.
	if _, err := el.SignAuth(offline.SigningMessage(make([]byte, offline.SignedSize))); !errors.Is(err, wallet.ErrRefusedToSign) {
		t.Fatalf("signed a record-shaped message: %v", err)
	}
	if _, err := el.SignAuth([]byte(api.RequestTag + "GET\n/v1/wallet")); err != nil {
		t.Fatal(err)
	}
}

func TestWrongPINLocksOutThenWipes(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	clock := func() time.Time { return now }
	if _, err := wallet.CreateSealedElement(dir, pin, nil, wallet.ElementOptions{KDF: wallet.TestKDF, Now: clock}); err != nil {
		t.Fatal(err)
	}
	el, _ := wallet.OpenSealedElement(dir, nil, wallet.ElementOptions{KDF: wallet.TestKDF, Now: clock})
	for i := 1; i <= 4; i++ {
		if err := el.Unlock("000000"); !errors.Is(err, wallet.ErrWrongPIN) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_ = el.Unlock("000000") // 5th: starts the lockout
	if err := el.Unlock(pin); !errors.Is(err, wallet.ErrLockedOut) {
		t.Fatalf("correct PIN during lockout: %v", err)
	}
	for i := 6; i <= 10; i++ {
		now = now.Add(time.Hour)
		err := el.Unlock("000000")
		if i == 10 && !errors.Is(err, wallet.ErrWiped) {
			t.Fatalf("10th wrong PIN: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "element.sealed")); !os.IsNotExist(err) {
		t.Fatal("element not wiped")
	}
	if _, err := wallet.OpenSealedElement(dir, nil, wallet.ElementOptions{}); !errors.Is(err, wallet.ErrWiped) {
		t.Fatalf("open after wipe: %v", err)
	}
}

func TestHardwareSealedWalletCannotMoveToAnotherDevice(t *testing.T) {
	root, _ := emulator.NewRoot("root")
	ksA, _ := emulator.NewAndroidKeyStore(root, attest.AndroidStrongBox)
	ksB, _ := emulator.NewAndroidKeyStore(root, attest.AndroidStrongBox)
	dirA, dirB := t.TempDir(), t.TempDir()
	if _, err := wallet.CreateSealedElement(dirA, pin, ksA, wallet.ElementOptions{KDF: wallet.TestKDF}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dirA, "element.sealed"))
	_ = os.WriteFile(filepath.Join(dirB, "element.sealed"), b, 0o600)
	el, _ := wallet.OpenSealedElement(dirB, ksB, wallet.ElementOptions{KDF: wallet.TestKDF})
	if err := el.Unlock(pin); err == nil {
		t.Fatal("copied wallet opened on another device's hardware with the right PIN")
	}
	own, _ := wallet.OpenSealedElement(dirA, ksA, wallet.ElementOptions{KDF: wallet.TestKDF})
	if err := own.Unlock(pin); err != nil {
		t.Fatalf("own device: %v", err)
	}
}

func TestHardwareElementSignsWithP256(t *testing.T) {
	f := newFixture()
	root, _ := emulator.NewRoot("root")
	ks, _ := emulator.NewAppleKeyStore(root, "TEAM.app")
	el, _ := wallet.CreateSealedElement(t.TempDir(), pin, ks, wallet.ElementOptions{KDF: wallet.TestKDF})
	f.provision(t, el, 500_00)
	raw, err := el.Pay(3, 10_00, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ks.PublicKey()
	if err := offline.VerifyRecordSignature(raw, offline.AlgP256, pub); err != nil {
		t.Fatalf("P-256 record: %v", err)
	}
}

func TestWeakPINRejected(t *testing.T) {
	if _, err := wallet.CreateSealedElement(t.TempDir(), "1234", nil, wallet.ElementOptions{KDF: wallet.TestKDF}); !errors.Is(err, wallet.ErrWeakPIN) {
		t.Fatalf("weak PIN: %v", err)
	}
}
