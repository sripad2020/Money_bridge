package offline

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// NormalizePhone converts an Indian or international phone number to E.164.
// "98765 43210", "+91-98765-43210" and "919876543210" all become "+919876543210".
func NormalizePhone(s string) (string, error) {
	var d strings.Builder
	plus := false
	for i, r := range strings.TrimSpace(s) {
		switch {
		case r >= '0' && r <= '9':
			d.WriteRune(r)
		case r == '+' && i == 0:
			plus = true
		case r == ' ' || r == '-' || r == '(' || r == ')':
		default:
			return "", fmt.Errorf("offline: phone %q contains %q", s, r)
		}
	}
	digits := d.String()
	switch {
	case plus && len(digits) >= 8 && len(digits) <= 15:
		return "+" + digits, nil
	case !plus && len(digits) == 10 && digits[0] >= '6':
		return "+91" + digits, nil
	case !plus && len(digits) == 12 && strings.HasPrefix(digits, "91"):
		return "+" + digits, nil
	}
	return "", fmt.Errorf("offline: %q is not a valid phone number", s)
}

// PayeeIDForPhone derives the 8-byte payee ID of a phone number. Any device
// can compute it offline, so a payment can be addressed by mobile number
// even to someone who has not registered yet; the server credits them when
// they do.
func PayeeIDForPhone(phone string) (uint64, error) {
	p, err := NormalizePhone(phone)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256([]byte("PSTCO-PAYEE-1\n" + p))
	id := binary.BigEndian.Uint64(sum[:8])
	if id == 0 {
		id = 1
	}
	return id, nil
}

// FormatID renders a device or payee ID as 16 hex digits.
func FormatID(id uint64) string { return fmt.Sprintf("%016x", id) }

// ParseID parses 16 hex digits.
func ParseID(s string) (uint64, error) {
	var id uint64
	if len(s) != 16 {
		return 0, fmt.Errorf("offline: id %q must be 16 hex digits", s)
	}
	if _, err := fmt.Sscanf(s, "%016x", &id); err != nil {
		return 0, fmt.Errorf("offline: id %q: %v", s, err)
	}
	return id, nil
}

// ---------------------------------------------------------------- directory

// DirectoryEntry is a listed payee, used to confirm names offline.
type DirectoryEntry struct {
	PayeeID string `json:"payee_id"`
	Phone   string `json:"phone"`
	Name    string `json:"name"`
}

// Directory is the bank-signed list of listed payees and revoked devices.
type Directory struct {
	Version  int64            `json:"version"`
	IssuedAt int64            `json:"issued_at"`
	Entries  []DirectoryEntry `json:"entries"`
	Revoked  []string         `json:"revoked_devices"`
}

// SignedDirectory carries the exact signed bytes, so no canonicalisation is needed.
type SignedDirectory struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

const directoryTag = "PSTCO-DIR-1\n"

// SignDirectory serialises and signs a directory.
func SignDirectory(d *Directory, sign func(msg []byte) []byte) (*SignedDirectory, error) {
	sort.Slice(d.Entries, func(i, j int) bool { return d.Entries[i].PayeeID < d.Entries[j].PayeeID })
	sort.Strings(d.Revoked)
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return &SignedDirectory{Payload: b, Signature: sign(append([]byte(directoryTag), b...))}, nil
}

// Open verifies the CA signature and decodes the directory.
func (s *SignedDirectory) Open(caPub ed25519.PublicKey) (*Directory, error) {
	if len(caPub) != ed25519.PublicKeySize || !ed25519.Verify(caPub, append([]byte(directoryTag), s.Payload...), s.Signature) {
		return nil, errors.New("offline: directory not signed by the bank CA")
	}
	var d Directory
	if err := json.Unmarshal(s.Payload, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Lookup finds a listed payee by phone number.
func (d *Directory) Lookup(phone string) (*DirectoryEntry, bool) {
	p, err := NormalizePhone(phone)
	if err != nil {
		return nil, false
	}
	for i := range d.Entries {
		if d.Entries[i].Phone == p {
			return &d.Entries[i], true
		}
	}
	return nil, false
}

// IsRevoked reports whether a device is on the revocation list.
func (d *Directory) IsRevoked(deviceID uint64) bool {
	id := FormatID(deviceID)
	for _, r := range d.Revoked {
		if r == id {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------- QR payloads

const (
	paymentQRPrefix = "PSTCO1:"
	payeeQRPrefix   = "PSTCOPAYEE1:"
)

// EncodePaymentQR packs a record and the payer's certificate for QR or NFC.
// The payee needs the certificate to verify the payment with no signal.
func EncodePaymentQR(record, cert []byte) string {
	return paymentQRPrefix + base64.RawURLEncoding.EncodeToString(append(append([]byte(nil), record...), cert...))
}

// DecodePaymentQR splits a payment QR payload into record and certificate.
func DecodePaymentQR(s string) (record, cert []byte, err error) {
	if !strings.HasPrefix(s, paymentQRPrefix) {
		return nil, nil, errors.New("offline: not a PSTCO payment code")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, paymentQRPrefix))
	if err != nil || len(b) <= RecordSize {
		return nil, nil, errors.New("offline: corrupt payment code")
	}
	return b[:RecordSize], b[RecordSize:], nil
}

// PayeeCard is what a payee shows as a QR code to be paid.
type PayeeCard struct {
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

// EncodePayeeQR encodes a payee card.
func EncodePayeeQR(phone, name string) (string, error) {
	p, err := NormalizePhone(phone)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(PayeeCard{Phone: p, Name: name})
	return payeeQRPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodePayeeQR decodes a payee card.
func DecodePayeeQR(s string) (*PayeeCard, error) {
	if !strings.HasPrefix(s, payeeQRPrefix) {
		return nil, errors.New("offline: not a PSTCO payee code")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, payeeQRPrefix))
	if err != nil {
		return nil, errors.New("offline: corrupt payee code")
	}
	var c PayeeCard
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, errors.New("offline: corrupt payee code")
	}
	if c.Phone, err = NormalizePhone(c.Phone); err != nil {
		return nil, err
	}
	return &c, nil
}

// ------------------------------------------------------- offline verification

// ErrPayment reports a payment the payee must not accept.
var ErrPayment = errors.New("offline: payment rejected")

// VerifyPayment is what a payee device runs with no signal: it checks the
// payer certificate against the bank CA, the record signature against the
// certificate key, the limit, the expiry and the payee.
func VerifyPayment(record, cert []byte, caPub ed25519.PublicKey, payee uint64, now time.Time) (*Record, *DeviceCert, error) {
	r, err := ParseRecord(record)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPayment, err)
	}
	c, n, err := ParseDeviceCert(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPayment, err)
	}
	if n != len(cert) {
		return nil, nil, fmt.Errorf("%w: trailing bytes after certificate", ErrPayment)
	}
	if err := c.Verify(caPub, now); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPayment, err)
	}
	if r.DeviceID != c.DeviceID {
		return nil, nil, fmt.Errorf("%w: certificate is for another device", ErrPayment)
	}
	if err := VerifyRecordSignature(record, c.Alg, c.PublicKey); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPayment, err)
	}
	if r.AmountPaise > c.PerPaymentLimit {
		return nil, nil, fmt.Errorf("%w: amount above the payer's per-payment limit", ErrPayment)
	}
	if uint32(now.Unix()) > r.Expiry {
		return nil, nil, fmt.Errorf("%w: payment expired", ErrPayment)
	}
	if payee != 0 && r.PayeeID != payee {
		return nil, nil, fmt.Errorf("%w: payment is addressed to someone else", ErrPayment)
	}
	return r, c, nil
}
