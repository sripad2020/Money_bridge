// Package wallet is the PSTCO-Pay device SDK: a secure element abstraction,
// a sealed element that works with or without secure hardware, and a Wallet
// that registers the device, holds the offline balance, pays and accepts
// payments with no signal, queues SMS, and syncs with the payment server.
package wallet

import (
	"errors"
	"time"

	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
)

// Errors returned by elements and wallets.
var (
	ErrLocked         = errors.New("wallet: locked")
	ErrWrongPIN       = errors.New("wallet: wrong PIN")
	ErrLockedOut      = errors.New("wallet: too many wrong PINs, try later")
	ErrWiped          = errors.New("wallet: wiped after repeated wrong PINs")
	ErrNotProvisioned = errors.New("wallet: device not registered")
	ErrNoReserve      = errors.New("wallet: no offline balance loaded")
	ErrReserveExpired = errors.New("wallet: offline balance expired, sync to renew")
	ErrInsufficient   = errors.New("wallet: insufficient offline balance")
	ErrOverLimit      = errors.New("wallet: amount above the per-payment limit")
	ErrRefusedToSign  = errors.New("wallet: element refuses to sign this message")
	ErrCompromised    = errors.New("wallet: runtime protection blocked this action")
	ErrWeakPIN        = errors.New("wallet: PIN must be at least 6 digits")
)

// ElementInfo describes an element.
type ElementInfo struct {
	Kind string      // software | android-strongbox | android-tee | ios-secure-enclave | sim-applet
	Alg  offline.Alg // signature algorithm of the device key
}

// ElementState is an element's public state.
type ElementState struct {
	Locked          bool
	DeviceID        uint64
	Provisioned     bool
	ReserveID       uint64
	BalancePaise    int64
	NextCounter     uint32
	ChainHead       [offline.HashSize]byte
	Expiry          uint32
	PerPaymentLimit int64
}

// Element is the device's secure element: it owns the signing key, the
// offline balance and the payment counter, and it is the only component
// that can produce a payment record.
//
// Implementations: SealedElement (this package; software key or a hardware
// KeyStore), a SIM applet bridged through sdk/mobile, and the emulators in
// sdk/wallet/emulator.
type Element interface {
	Info() ElementInfo
	PublicKey() ([]byte, error)
	// Attest returns platform evidence over challenge; Format "none" when
	// the element has no secure hardware.
	Attest(challenge []byte) (api.Attestation, error)
	// SignAuth signs API authentication messages only (api.RequestTag or
	// api.RegisterTag prefixed); anything else is refused.
	SignAuth(msg []byte) ([]byte, error)
	Unlock(pin string) error
	Lock()
	// Provision stores the device certificate issued at registration.
	Provision(cert []byte, caPublicKey []byte) error
	// LoadReserve loads a bank-signed reserve instruction.
	LoadReserve(instruction []byte) error
	// Pay atomically checks limits, deducts the balance, advances the
	// counter, links and signs a record, and persists before returning it.
	Pay(payeeID uint64, amountPaise int64, now time.Time) ([]byte, error)
	State() (ElementState, error)
}

// KeyStore is a hardware-backed signing key (Android Keystore StrongBox/TEE
// or the iOS Secure Enclave) supplied by the host app. The key never leaves
// the hardware; SealedElement keeps the balance and counter sealed in app
// storage around it.
type KeyStore interface {
	Kind() string
	Alg() offline.Alg
	PublicKey() ([]byte, error)
	// Sign returns a 64-byte signature (use offline.ECDSADERToRaw on DER).
	Sign(msg []byte) ([]byte, error)
	Attest(challenge []byte) (api.Attestation, error)
}

// Sealer is optionally implemented by a KeyStore whose hardware can encrypt
// with a non-exportable key. SealedElement then wraps its data key with it,
// so a copied wallet file cannot be opened on another device even with the PIN.
type Sealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Unseal(ciphertext []byte) ([]byte, error)
}
