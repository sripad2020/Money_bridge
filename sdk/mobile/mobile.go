// Package mobile is the gomobile-friendly facade of the PSTCO-Pay wallet SDK
// for Android and iOS apps:
//
//	gomobile bind -target=android -o pstco.aar ./sdk/mobile
//	gomobile bind -target=ios     -o Pstco.xcframework ./sdk/mobile
//
// The host app implements NativeKeyStore in Kotlin (Android Keystore with
// StrongBox or TEE) or Swift (Secure Enclave with App Attest) and passes it
// to NewWallet; pass nil on devices without secure hardware. Complex results
// are returned as JSON strings because gomobile only binds simple types.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"pstcopay/sdk/client"
	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
	"pstcopay/sdk/wallet"
)

// NativeKeyStore is a hardware key implemented by the host app.
type NativeKeyStore interface {
	// Kind is android-strongbox, android-tee or ios-secure-enclave.
	Kind() string
	// PublicKey returns the 65-byte uncompressed P-256 public key.
	PublicKey() ([]byte, error)
	// SignDER signs SHA-256(msg) with ECDSA and returns the DER signature
	// exactly as Android Keystore or SecKeyCreateSignature produce it.
	SignDER(msg []byte) ([]byte, error)
	// AttestationJSON returns {"format":"android-key","chain":[base64 DER...]}
	// or {"format":"apple-appattest","object":"<base64 CBOR>"} for challenge.
	AttestationJSON(challenge []byte) (string, error)
}

type nativeAdapter struct{ n NativeKeyStore }

func (a nativeAdapter) Kind() string               { return a.n.Kind() }
func (a nativeAdapter) Alg() offline.Alg           { return offline.AlgP256 }
func (a nativeAdapter) PublicKey() ([]byte, error) { return a.n.PublicKey() }
func (a nativeAdapter) Sign(m []byte) ([]byte, error) {
	der, err := a.n.SignDER(m)
	if err != nil {
		return nil, err
	}
	return offline.ECDSADERToRaw(der)
}
func (a nativeAdapter) Attest(ch []byte) (api.Attestation, error) {
	s, err := a.n.AttestationJSON(ch)
	if err != nil {
		return api.Attestation{}, err
	}
	var att api.Attestation
	return att, json.Unmarshal([]byte(s), &att)
}

// Wallet wraps the SDK wallet for mobile bindings.
type Wallet struct {
	w       *wallet.Wallet
	timeout time.Duration
}

// NewWallet opens (or creates, on first use) a wallet in dir. serverURL is
// the offline API base URL; caPEM pins a private server CA ("" for system
// roots). native may be nil on devices without secure hardware.
func NewWallet(dir, serverURL, caPEM, pin string, native NativeKeyStore) (*Wallet, error) {
	var ks wallet.KeyStore
	if native != nil {
		ks = nativeAdapter{native}
	}
	var el wallet.Element
	var err error
	if _, statErr := os.Stat(filepath.Join(dir, "element.sealed")); statErr == nil {
		el, err = wallet.OpenSealedElement(dir, ks, wallet.ElementOptions{})
	} else {
		el, err = wallet.CreateSealedElement(dir, pin, ks, wallet.ElementOptions{})
	}
	if err != nil {
		return nil, err
	}
	var hc = client.NewHTTPClient(nil)
	if caPEM != "" {
		hc = client.NewHTTPClient([]byte(caPEM))
	}
	w, err := wallet.New(wallet.Config{Dir: dir, Element: el, Client: client.New(serverURL, hc)})
	if err != nil {
		return nil, err
	}
	return &Wallet{w: w, timeout: 30 * time.Second}, nil
}

func (m *Wallet) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), m.timeout)
}

func asJSON(v any, err error) (string, error) {
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// Unlock opens the wallet with the PIN.
func (m *Wallet) Unlock(pin string) error { return m.w.Unlock(pin) }

// Lock wipes keys from memory.
func (m *Wallet) Lock() { m.w.Lock() }

// StartAccount sends an OTP; it returns the OTP only from a development server.
func (m *Wallet) StartAccount(phone, name string, listed bool) (string, error) {
	c, cancel := m.ctx()
	defer cancel()
	return m.w.StartAccount(c, phone, name, listed)
}

// VerifyAccount confirms the OTP.
func (m *Wallet) VerifyAccount(phone, otp string) error {
	c, cancel := m.ctx()
	defer cancel()
	return m.w.VerifyAccount(c, phone, otp)
}

// Register registers the device and returns the registration as JSON.
func (m *Wallet) Register() (string, error) {
	c, cancel := m.ctx()
	defer cancel()
	return asJSON(m.w.Register(c))
}

// Deposit funds the online wallet ("1000.00" rupees). pin re-confirms the
// user; pass "" when Config.Biometric is used.
func (m *Wallet) Deposit(rupees, pin string) (string, error) {
	p, err := offline.ParseINR(rupees)
	if err != nil {
		return "", err
	}
	a, err := m.w.Approve(wallet.Intent{Op: wallet.OpDeposit, AmountPaise: p}, pin)
	if err != nil {
		return "", err
	}
	c, cancel := m.ctx()
	defer cancel()
	return asJSON(m.w.Deposit(c, p, a))
}

// CreateReserve loads an offline balance ("500" rupees).
func (m *Wallet) CreateReserve(rupees, pin string) (string, error) {
	p, err := offline.ParseINR(rupees)
	if err != nil {
		return "", err
	}
	a, err := m.w.Approve(wallet.Intent{Op: wallet.OpReserve, AmountPaise: p}, pin)
	if err != nil {
		return "", err
	}
	c, cancel := m.ctx()
	defer cancel()
	return asJSON(m.w.CreateReserve(c, p, a))
}

// QuotePhone resolves a payee offline; show the name before paying.
func (m *Wallet) QuotePhone(phone string) (string, error) { return asJSON(m.w.QuotePhone(phone)) }

// PayPhone pays a mobile number offline. delivery is "qr" or "sms"; pin
// approves exactly this payee and amount, once.
func (m *Wallet) PayPhone(phone, rupees, delivery, pin string) (string, error) {
	p, err := offline.ParseINR(rupees)
	if err != nil {
		return "", err
	}
	q, err := m.w.QuotePhone(phone)
	if err != nil {
		return "", err
	}
	a, err := m.w.Approve(wallet.Intent{Op: wallet.OpPay, AmountPaise: p, PayeeID: q.PayeeID}, pin)
	if err != nil {
		return "", err
	}
	return asJSON(m.w.Pay(q, p, delivery, a))
}

// PayCard pays a scanned payee QR card.
func (m *Wallet) PayCard(cardQR, rupees, pin string) (string, error) {
	p, err := offline.ParseINR(rupees)
	if err != nil {
		return "", err
	}
	card, err := offline.DecodePayeeQR(cardQR)
	if err != nil {
		return "", err
	}
	payee, _ := offline.PayeeIDForPhone(card.Phone)
	a, err := m.w.Approve(wallet.Intent{Op: wallet.OpPay, AmountPaise: p, PayeeID: payee}, pin)
	if err != nil {
		return "", err
	}
	return asJSON(m.w.PayCard(cardQR, p, a))
}

// Accept verifies a payment code received by QR or NFC, offline.
func (m *Wallet) Accept(code string) (string, error) { return asJSON(m.w.Accept(code)) }

// AcceptSMS verifies a binary SMS payment, offline.
func (m *Wallet) AcceptSMS(payload []byte) (string, error) { return asJSON(m.w.AcceptBytes(payload)) }

// PendingSMS lists messages the app must send when signal returns (JSON).
func (m *Wallet) PendingSMS() (string, error) { return asJSON(m.w.PendingSMS(), nil) }

// MarkSMSSent records the outcome of sending a queued message.
func (m *Wallet) MarkSMSSent(id string, sent bool) error { return m.w.MarkSMSSent(id, sent) }

// QueueServerSMS queues unsynced records for sync over GSM; returns how many.
func (m *Wallet) QueueServerSMS() (int, error) { return m.w.QueueServerSMS() }

// Sync uploads payments and refreshes the directory (JSON report).
func (m *Wallet) Sync() (string, error) {
	c, cancel := m.ctx()
	defer cancel()
	return asJSON(m.w.Sync(c))
}

// Balance returns the local balance (JSON).
func (m *Wallet) Balance() (string, error) { return asJSON(m.w.Balance()) }

// PayeeQR returns this account's card for others to scan.
func (m *Wallet) PayeeQR() (string, error) { return m.w.PayeeQR() }

// ErrNoNative is returned when hardware is required but none was supplied.
var ErrNoNative = errors.New("mobile: no native key store")
