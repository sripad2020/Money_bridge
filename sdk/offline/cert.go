package offline

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Device certificate layout:
//
//	0   1   version (0x01)
//	1   8   device ID
//	9   8   owner payee ID
//	17  1   algorithm
//	18  1   trust level
//	19  5   per-payment limit (paise)
//	24  5   maximum reserve (paise)
//	29  4   issued at (unix seconds)
//	33  4   expires at (unix seconds)
//	37  1   public key length N
//	38  N   public key
//	38+N 64 Ed25519 signature by the bank CA over CertTag || bytes 0..37+N
const (
	CertV1  = 0x01
	certTag = "PSTCO-CERT-1"
	certFix = 38
)

// ErrCert reports a malformed, expired or untrusted device certificate.
var ErrCert = errors.New("offline: invalid device certificate")

// DeviceCert binds a device ID to its public key, owner, trust level and limits.
type DeviceCert struct {
	Version         byte
	DeviceID        uint64
	OwnerPayee      uint64
	Alg             Alg
	Trust           Trust
	PerPaymentLimit int64
	MaxReserve      int64
	IssuedAt        uint32
	ExpiresAt       uint32
	PublicKey       []byte
	Signature       [64]byte
}

func (c *DeviceCert) body() ([]byte, error) {
	if c.Version != CertV1 {
		return nil, fmt.Errorf("%w: version %d", ErrCert, c.Version)
	}
	if len(c.PublicKey) != c.Alg.PublicKeySize() || len(c.PublicKey) == 0 {
		return nil, fmt.Errorf("%w: public key size %d for %s", ErrCert, len(c.PublicKey), c.Alg)
	}
	b := make([]byte, certFix, certFix+len(c.PublicKey)+64)
	b[0] = c.Version
	binary.BigEndian.PutUint64(b[1:9], c.DeviceID)
	binary.BigEndian.PutUint64(b[9:17], c.OwnerPayee)
	b[17] = byte(c.Alg)
	b[18] = byte(c.Trust)
	if err := PutAmount(b[19:24], c.PerPaymentLimit); err != nil {
		return nil, fmt.Errorf("%w: per-payment limit: %v", ErrCert, err)
	}
	if err := PutAmount(b[24:29], c.MaxReserve); err != nil {
		return nil, fmt.Errorf("%w: max reserve: %v", ErrCert, err)
	}
	binary.BigEndian.PutUint32(b[29:33], c.IssuedAt)
	binary.BigEndian.PutUint32(b[33:37], c.ExpiresAt)
	b[37] = byte(len(c.PublicKey))
	return append(b, c.PublicKey...), nil
}

// Sign signs the certificate with the CA signing function (Ed25519).
func (c *DeviceCert) Sign(sign func(msg []byte) []byte) error {
	b, err := c.body()
	if err != nil {
		return err
	}
	copy(c.Signature[:], sign(append([]byte(certTag), b...)))
	return nil
}

// Marshal encodes the signed certificate.
func (c *DeviceCert) Marshal() ([]byte, error) {
	b, err := c.body()
	if err != nil {
		return nil, err
	}
	return append(b, c.Signature[:]...), nil
}

// ParseDeviceCert decodes a certificate at the start of b and returns it with
// the number of bytes it occupies.
func ParseDeviceCert(b []byte) (*DeviceCert, int, error) {
	if len(b) < certFix+64 {
		return nil, 0, fmt.Errorf("%w: too short", ErrCert)
	}
	n := int(b[37])
	size := certFix + n + 64
	if len(b) < size {
		return nil, 0, fmt.Errorf("%w: truncated", ErrCert)
	}
	c := &DeviceCert{Version: b[0]}
	c.DeviceID = binary.BigEndian.Uint64(b[1:9])
	c.OwnerPayee = binary.BigEndian.Uint64(b[9:17])
	c.Alg = Alg(b[17])
	c.Trust = Trust(b[18])
	var err error
	if c.PerPaymentLimit, err = Amount(b[19:24]); err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrCert, err)
	}
	if c.MaxReserve, err = Amount(b[24:29]); err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrCert, err)
	}
	c.IssuedAt = binary.BigEndian.Uint32(b[29:33])
	c.ExpiresAt = binary.BigEndian.Uint32(b[33:37])
	c.PublicKey = append([]byte(nil), b[certFix:certFix+n]...)
	copy(c.Signature[:], b[certFix+n:size])
	if c.Version != CertV1 || n != c.Alg.PublicKeySize() {
		return nil, 0, fmt.Errorf("%w: version or key size", ErrCert)
	}
	return c, size, nil
}

// Verify checks the CA signature and validity window.
func (c *DeviceCert) Verify(caPub ed25519.PublicKey, now time.Time) error {
	b, err := c.body()
	if err != nil {
		return err
	}
	if len(caPub) != ed25519.PublicKeySize || !ed25519.Verify(caPub, append([]byte(certTag), b...), c.Signature[:]) {
		return fmt.Errorf("%w: not signed by the bank CA", ErrCert)
	}
	t := uint32(now.Unix())
	if t+300 < c.IssuedAt || t > c.ExpiresAt {
		return fmt.Errorf("%w: outside validity window", ErrCert)
	}
	return nil
}

// KeyFingerprint identifies a public key (first 8 bytes of SHA-256, hex).
func KeyFingerprint(pub []byte) string {
	s := sha256.Sum256(pub)
	return fmt.Sprintf("%x", s[:8])
}
