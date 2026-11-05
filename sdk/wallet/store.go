package wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
)

const storeFile = "wallet.sealed"

// SentPayment is a payment this device signed.
type SentPayment struct {
	Counter     uint32    `json:"counter"`
	Raw         []byte    `json:"raw"`
	PayeeID     uint64    `json:"payee_id"`
	PayeePhone  string    `json:"payee_phone,omitempty"`
	PayeeName   string    `json:"payee_name,omitempty"`
	AmountPaise int64     `json:"amount_paise"`
	Delivery    string    `json:"delivery"`
	CreatedAt   time.Time `json:"created_at"`
	Synced      bool      `json:"synced"`
	Status      string    `json:"status,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Receipt     []byte    `json:"receipt,omitempty"` // server-signed proof of acceptance
}

// ReceivedPayment is a payment this device accepted as payee.
type ReceivedPayment struct {
	DeviceID    uint64    `json:"device_id"`
	Counter     uint32    `json:"counter"`
	Raw         []byte    `json:"raw"`
	Cert        []byte    `json:"cert"`
	AmountPaise int64     `json:"amount_paise"`
	PayerPayee  uint64    `json:"payer_payee_id"`
	ReceivedAt  time.Time `json:"received_at"`
	Synced      bool      `json:"synced"`
	Status      string    `json:"status,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Receipt     []byte    `json:"receipt,omitempty"` // server-signed proof of acceptance
}

// OutgoingSMS is a message the host app must send through the phone's SMS
// API, then confirm with MarkSMSSent.
type OutgoingSMS struct {
	ID       string    `json:"id"`
	To       string    `json:"to"`
	Payload  []byte    `json:"payload"`
	Purpose  string    `json:"purpose"` // payee | server
	Counter  uint32    `json:"counter"`
	QueuedAt time.Time `json:"queued_at"`
	Attempts int       `json:"attempts"`
	Sent     bool      `json:"sent"`
}

type localData struct {
	AccountID     string                   `json:"account_id"`
	Phone         string                   `json:"phone"`
	Name          string                   `json:"name"`
	PayeeID       uint64                   `json:"payee_id"`
	DeviceID      uint64                   `json:"device_id"`
	Cert          []byte                   `json:"cert"`
	CAPublicKey   []byte                   `json:"ca_public_key"`
	ReceiptKey    []byte                   `json:"receipt_public_key"`
	Trust         string                   `json:"trust"`
	TrustNote     string                   `json:"trust_note"`
	Limits        api.Limits               `json:"limits"`
	Directory     *offline.SignedDirectory `json:"directory,omitempty"`
	Sent          []*SentPayment           `json:"sent"`
	Received      []*ReceivedPayment       `json:"received"`
	Outbox        []*OutgoingSMS           `json:"outbox"`
	PendingRsvKey string                   `json:"pending_reserve_key,omitempty"`
	PendingRsvAmt int64                    `json:"pending_reserve_amount,omitempty"`
	LastSync      time.Time                `json:"last_sync"`
}

type sealedStore struct {
	KDF  KDF    `json:"kdf"`
	Salt []byte `json:"salt"`
	Data []byte `json:"data"`
}

type localStore struct {
	path string
	key  []byte
	salt []byte
	kdf  KDF
	data *localData
}

func openLocalStore(dir, pin string, kdf KDF) (*localStore, error) {
	path := filepath.Join(dir, storeFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		salt := randomBytes(16)
		s := &localStore{path: path, key: kdf.derive(pin, salt), salt: salt, kdf: kdf, data: &localData{}}
		return s, s.save()
	}
	if err != nil {
		return nil, err
	}
	var f sealedStore
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("wallet: store corrupt: %w", err)
	}
	key := f.KDF.derive(pin, f.Salt)
	plain, err := open(key, f.Data, []byte("pstco-wallet"))
	if err != nil {
		zero(key)
		return nil, ErrWrongPIN
	}
	var d localData
	if err := json.Unmarshal(plain, &d); err != nil {
		return nil, err
	}
	return &localStore{path: path, key: key, salt: f.Salt, kdf: f.KDF, data: &d}, nil
}

func (s *localStore) save() error {
	plain, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	ct, err := seal(s.key, plain, []byte("pstco-wallet"))
	zero(plain)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(sealedStore{KDF: s.kdf, Salt: s.salt, Data: ct})
	return writeFileAtomic(s.path, b)
}

func (s *localStore) close() {
	zero(s.key)
	s.data = nil
}
