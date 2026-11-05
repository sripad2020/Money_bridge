package offline

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Reserve instruction layout:
//
//	0   1   version (0x01)
//	1   8   reserve ID
//	9   8   device ID
//	17  5   offline balance granted (paise)
//	22  4   first counter this reserve covers
//	26  5   per-payment limit (paise)
//	31  4   expiry (unix seconds); records carry this expiry
//	35  4   issued at (unix seconds)
//	39  64  Ed25519 signature by the bank CA over ReserveTag || bytes 0..38
//
// The first record signed under a reserve links to Genesis(), the first 16
// bytes of SHA-256 over the whole instruction, binding the chain to it.
const (
	ReserveV1   = 0x01
	ReserveSize = 103
	reserveTag  = "PSTCO-RSV-1"
)

// ErrReserve reports an invalid reserve instruction.
var ErrReserve = errors.New("offline: invalid reserve instruction")

// Reserve is a signed instruction loading an offline balance into a device.
type Reserve struct {
	Version         byte
	ReserveID       uint64
	DeviceID        uint64
	AmountPaise     int64
	CounterStart    uint32
	PerPaymentLimit int64
	Expiry          uint32
	IssuedAt        uint32
	Signature       [64]byte
}

func (r *Reserve) body() ([]byte, error) {
	if r.Version != ReserveV1 || r.ReserveID == 0 || r.DeviceID == 0 || r.CounterStart == 0 {
		return nil, fmt.Errorf("%w: missing fields", ErrReserve)
	}
	b := make([]byte, 39, ReserveSize)
	b[0] = r.Version
	binary.BigEndian.PutUint64(b[1:9], r.ReserveID)
	binary.BigEndian.PutUint64(b[9:17], r.DeviceID)
	if err := PutAmount(b[17:22], r.AmountPaise); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReserve, err)
	}
	binary.BigEndian.PutUint32(b[22:26], r.CounterStart)
	if err := PutAmount(b[26:31], r.PerPaymentLimit); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReserve, err)
	}
	binary.BigEndian.PutUint32(b[31:35], r.Expiry)
	binary.BigEndian.PutUint32(b[35:39], r.IssuedAt)
	return b, nil
}

// Sign signs the instruction with the CA signing function.
func (r *Reserve) Sign(sign func(msg []byte) []byte) error {
	b, err := r.body()
	if err != nil {
		return err
	}
	copy(r.Signature[:], sign(append([]byte(reserveTag), b...)))
	return nil
}

// Marshal encodes the signed instruction (103 bytes).
func (r *Reserve) Marshal() ([]byte, error) {
	b, err := r.body()
	if err != nil {
		return nil, err
	}
	return append(b, r.Signature[:]...), nil
}

// ParseReserve decodes an instruction without verifying it.
func ParseReserve(b []byte) (*Reserve, error) {
	if len(b) != ReserveSize || b[0] != ReserveV1 {
		return nil, fmt.Errorf("%w: size or version", ErrReserve)
	}
	r := &Reserve{Version: b[0]}
	r.ReserveID = binary.BigEndian.Uint64(b[1:9])
	r.DeviceID = binary.BigEndian.Uint64(b[9:17])
	var err error
	if r.AmountPaise, err = Amount(b[17:22]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReserve, err)
	}
	r.CounterStart = binary.BigEndian.Uint32(b[22:26])
	if r.PerPaymentLimit, err = Amount(b[26:31]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReserve, err)
	}
	r.Expiry = binary.BigEndian.Uint32(b[31:35])
	r.IssuedAt = binary.BigEndian.Uint32(b[35:39])
	copy(r.Signature[:], b[39:])
	return r, nil
}

// Verify checks the CA signature.
func (r *Reserve) Verify(caPub ed25519.PublicKey) error {
	b, err := r.body()
	if err != nil {
		return err
	}
	if len(caPub) != ed25519.PublicKeySize || !ed25519.Verify(caPub, append([]byte(reserveTag), b...), r.Signature[:]) {
		return fmt.Errorf("%w: not signed by the bank CA", ErrReserve)
	}
	return nil
}

// Genesis returns the previous-hash value of the first record under this reserve.
func ReserveGenesis(raw []byte) [HashSize]byte {
	sum := sha256.Sum256(raw)
	var h [HashSize]byte
	copy(h[:], sum[:HashSize])
	return h
}
