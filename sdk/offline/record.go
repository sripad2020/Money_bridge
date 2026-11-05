package offline

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Record layout (all integers unsigned, big-endian):
//
//	offset  size  field
//	0       1     version (0x01 = INR, amount in paise)
//	1       8     device ID
//	9       4     counter (starts at 1, +1 per payment)
//	13      5     amount in paise (40-bit)
//	18      8     payee ID
//	26      4     timestamp (unix seconds, informational)
//	30      4     expiry (unix seconds)
//	34      16    previous record hash (first 16 bytes of SHA-256)
//	50      64    signature over RecordTag || bytes 0..49
const (
	RecordSize  = 114
	SignedSize  = 50
	RecordV1    = 0x01
	recordTag   = "PSTCO-OFF-1"
	HashSize    = 16
	maxCounter  = 1<<32 - 1
	headerBytes = SignedSize
)

// ErrRecord reports a malformed record.
var ErrRecord = errors.New("offline: malformed record")

// Record is one offline payment.
type Record struct {
	Version     byte
	DeviceID    uint64
	Counter     uint32
	AmountPaise int64
	PayeeID     uint64
	Timestamp   uint32
	Expiry      uint32
	PrevHash    [HashSize]byte
	Signature   [64]byte
}

// SignedBytes returns the 50 bytes covered by the signature.
func (r *Record) SignedBytes() ([]byte, error) {
	if r.Version != RecordV1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrRecord, r.Version)
	}
	if r.DeviceID == 0 || r.Counter == 0 || r.PayeeID == 0 {
		return nil, fmt.Errorf("%w: device, counter and payee must be non-zero", ErrRecord)
	}
	b := make([]byte, SignedSize)
	b[0] = r.Version
	binary.BigEndian.PutUint64(b[1:9], r.DeviceID)
	binary.BigEndian.PutUint32(b[9:13], r.Counter)
	if err := PutAmount(b[13:18], r.AmountPaise); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint64(b[18:26], r.PayeeID)
	binary.BigEndian.PutUint32(b[26:30], r.Timestamp)
	binary.BigEndian.PutUint32(b[30:34], r.Expiry)
	copy(b[34:50], r.PrevHash[:])
	return b, nil
}

// SigningMessage returns the exact bytes a device signs for a record.
func SigningMessage(signed []byte) []byte {
	return append([]byte(recordTag), signed...)
}

// Marshal returns the full 114-byte record.
func (r *Record) Marshal() ([]byte, error) {
	b, err := r.SignedBytes()
	if err != nil {
		return nil, err
	}
	return append(b, r.Signature[:]...), nil
}

// ParseRecord decodes and structurally validates a 114-byte record. It does
// not verify the signature: use VerifyPayment or VerifyRecordSignature.
func ParseRecord(b []byte) (*Record, error) {
	if len(b) != RecordSize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrRecord, len(b), RecordSize)
	}
	if b[0] != RecordV1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrRecord, b[0])
	}
	r := &Record{Version: b[0]}
	r.DeviceID = binary.BigEndian.Uint64(b[1:9])
	r.Counter = binary.BigEndian.Uint32(b[9:13])
	amt, err := Amount(b[13:18])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecord, err)
	}
	r.AmountPaise = amt
	r.PayeeID = binary.BigEndian.Uint64(b[18:26])
	r.Timestamp = binary.BigEndian.Uint32(b[26:30])
	r.Expiry = binary.BigEndian.Uint32(b[30:34])
	copy(r.PrevHash[:], b[34:50])
	copy(r.Signature[:], b[50:114])
	if r.DeviceID == 0 || r.Counter == 0 || r.PayeeID == 0 {
		return nil, fmt.Errorf("%w: device, counter and payee must be non-zero", ErrRecord)
	}
	return r, nil
}

// RecordHash returns the chain hash of a full record: the first 16 bytes of
// SHA-256 over all 114 bytes.
func RecordHash(raw []byte) [HashSize]byte {
	sum := sha256.Sum256(raw)
	var h [HashSize]byte
	copy(h[:], sum[:HashSize])
	return h
}

// VerifyRecordSignature checks a raw record's signature with the device key.
func VerifyRecordSignature(raw []byte, alg Alg, pub []byte) error {
	if len(raw) != RecordSize {
		return fmt.Errorf("%w: %d bytes", ErrRecord, len(raw))
	}
	return VerifySignature(alg, pub, SigningMessage(raw[:SignedSize]), raw[SignedSize:])
}

// Nonce is the record's unique identity and the server's idempotency key.
func (r *Record) Nonce() string { return NonceFor(r.DeviceID, r.Counter) }

// NonceFor formats a device ID and counter as a nonce.
func NonceFor(deviceID uint64, counter uint32) string {
	return fmt.Sprintf("%016x:%d", deviceID, counter)
}
