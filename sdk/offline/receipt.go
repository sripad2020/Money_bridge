package offline

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

// Receipt layout (98 bytes): the server's signed acknowledgement that it
// accepted one record. A payee keeps it as proof for disputes.
//
//	0   1   version (0x01)
//	1   8   device ID
//	9   4   counter
//	13  16  record hash (RecordHash of the accepted 114 bytes)
//	29  1   status (1 accepted, 2 settled, 3 duplicate of an accepted record)
//	30  4   issued at (unix seconds)
//	34  64  Ed25519 signature by the server's offline key over ReceiptTag || bytes 0..33
const (
	ReceiptSize = 98
	receiptTag  = "PSTCO-RCPT-1"

	ReceiptAccepted  = 1
	ReceiptSettled   = 2
	ReceiptDuplicate = 3
)

// ErrReceipt reports a receipt that does not prove acceptance of a record.
var ErrReceipt = errors.New("offline: invalid receipt")

// SignReceipt issues a receipt for a raw record.
func SignReceipt(raw []byte, status byte, issuedAt uint32, sign func([]byte) []byte) ([]byte, error) {
	r, err := ParseRecord(raw)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 34, ReceiptSize)
	b[0] = 1
	binary.BigEndian.PutUint64(b[1:9], r.DeviceID)
	binary.BigEndian.PutUint32(b[9:13], r.Counter)
	h := RecordHash(raw)
	copy(b[13:29], h[:])
	b[29] = status
	binary.BigEndian.PutUint32(b[30:34], issuedAt)
	return append(b, sign(append([]byte(receiptTag), b...))...), nil
}

// VerifyReceipt checks that receipt was signed by the server key and covers
// exactly this record, and returns its status.
func VerifyReceipt(receipt, raw []byte, serverPub ed25519.PublicKey) (byte, error) {
	if len(receipt) != ReceiptSize || receipt[0] != 1 {
		return 0, fmt.Errorf("%w: size or version", ErrReceipt)
	}
	if len(serverPub) != ed25519.PublicKeySize || !ed25519.Verify(serverPub, append([]byte(receiptTag), receipt[:34]...), receipt[34:]) {
		return 0, fmt.Errorf("%w: not signed by the server", ErrReceipt)
	}
	r, err := ParseRecord(raw)
	if err != nil {
		return 0, err
	}
	h := RecordHash(raw)
	if binary.BigEndian.Uint64(receipt[1:9]) != r.DeviceID || binary.BigEndian.Uint32(receipt[9:13]) != r.Counter ||
		!bytes.Equal(receipt[13:29], h[:]) {
		return 0, fmt.Errorf("%w: receipt is for a different record", ErrReceipt)
	}
	return receipt[29], nil
}
