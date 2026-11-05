package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Wallet access guardrail.
//
// Unlocking the wallet authenticates the user for a session. It does not
// authorise any money movement. Every payment, deposit and reserve also needs
// an Approval: a single-use 256-bit token from crypto/rand, issued only after
// the user re-confirms with the PIN (or a biometric check run by the host
// app), bound to one exact intent (operation, amount, payee) and valid for a
// short time. Code that can reach an unlocked wallet but has no approval, such
// as malware or a compromised UI layer, cannot move money. Presenting a used,
// expired, forged or mismatched token counts as an access violation; three
// violations lock the wallet.

// Operations that need approval.
const (
	OpPay     = "pay"
	OpDeposit = "deposit"
	OpReserve = "reserve"
)

// Errors of the approval guardrail.
var (
	ErrApprovalRequired = errors.New("wallet: this operation needs a fresh approval")
	ErrApprovalInvalid  = errors.New("wallet: approval is invalid, used, expired or for a different operation")
	ErrAccessDenied     = errors.New("wallet: locked after repeated access violations")
)

// Intent is exactly what the user approves.
type Intent struct {
	Op          string
	AmountPaise int64
	PayeeID     uint64 // pay only
}

func (i Intent) digest() [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("pstco-intent/1|%s|%d|%016x", i.Op, i.AmountPaise, i.PayeeID)))
}

// Approval authorises one intent once.
type Approval struct {
	Token     string // 64 hex characters, unpredictable
	Intent    Intent
	ExpiresAt time.Time
}

type pendingApproval struct {
	intent [32]byte
	exp    time.Time
}

const (
	maxViolations   = 3
	maxApprovePINs  = 5
	defaultApproval = 60 * time.Second
)

// Approve re-verifies the PIN and issues an approval for one intent. With a
// Config.Biometric hook set, pin may be empty and the hook decides.
func (w *Wallet) Approve(intent Intent, pin string) (*Approval, error) {
	if err := w.protect(); err != nil {
		return nil, err
	}
	switch intent.Op {
	case OpPay, OpDeposit, OpReserve:
	default:
		return nil, fmt.Errorf("wallet: unknown operation %q", intent.Op)
	}
	if intent.AmountPaise < 0 || (intent.Op == OpPay && (intent.AmountPaise == 0 || intent.PayeeID == 0)) {
		return nil, errors.New("wallet: approval needs a positive amount and, for payments, a payee")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.store == nil {
		return nil, ErrLocked
	}
	if pin == "" && w.cfg.Biometric != nil {
		if err := w.cfg.Biometric(intent); err != nil {
			return nil, fmt.Errorf("wallet: biometric check failed: %w", err)
		}
	} else {
		candidate := w.store.kdf.derive(pin, w.store.salt)
		ok := subtle.ConstantTimeCompare(candidate, w.store.key) == 1
		zero(candidate)
		if !ok {
			w.pinFails++
			if w.pinFails >= maxApprovePINs {
				w.lockLocked()
				return nil, ErrLockedOut
			}
			return nil, ErrWrongPIN
		}
		w.pinFails = 0
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	tok := hex.EncodeToString(b)
	ttl := w.cfg.ApprovalTTL
	if ttl <= 0 {
		ttl = defaultApproval
	}
	exp := w.now().Add(ttl)
	if w.approvals == nil {
		w.approvals = map[[32]byte]pendingApproval{}
	}
	for k, p := range w.approvals { // drop stale ones
		if w.now().After(p.exp) {
			delete(w.approvals, k)
		}
	}
	w.approvals[sha256.Sum256([]byte(tok))] = pendingApproval{intent: intent.digest(), exp: exp}
	return &Approval{Token: tok, Intent: intent, ExpiresAt: exp}, nil
}

// consumeLocked checks and burns an approval. The caller holds w.mu.
func (w *Wallet) consumeLocked(a *Approval, want Intent) error {
	if a == nil {
		return ErrApprovalRequired
	}
	key := sha256.Sum256([]byte(a.Token))
	p, ok := w.approvals[key]
	delete(w.approvals, key) // single use, whatever happens next
	wantD := want.digest()
	if !ok || w.now().After(p.exp) || subtle.ConstantTimeCompare(p.intent[:], wantD[:]) != 1 {
		w.violations++
		if w.violations >= maxViolations {
			w.lockLocked()
			return ErrAccessDenied
		}
		return ErrApprovalInvalid
	}
	return nil
}

// lockLocked locks the wallet; the caller holds w.mu.
func (w *Wallet) lockLocked() {
	if w.store != nil {
		w.store.close()
		w.store = nil
	}
	w.approvals, w.violations, w.pinFails = nil, 0, 0
	w.el.Lock()
}
