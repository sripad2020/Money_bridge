// Package offline is the PSTCO-Pay offline payment wire format, shared by
// devices, payees and the payment server: amounts, the 114-byte payment
// record, device certificates, reserve instructions, the signed payee
// directory, QR payloads and offline verification.
//
// Everything here is pure Go with no network or storage, so it can be used
// from servers, CLIs and mobile apps (through gomobile) alike.
package offline

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxAmountPaise is the largest amount the 40-bit amount field can carry:
// 1,099,511,627,775 paise (about ₹1,099.5 crore). Real limits are far lower
// and are enforced separately by the device certificate and the reserve.
const MaxAmountPaise int64 = 1<<40 - 1

// AmountSize is the encoded size of an amount.
const AmountSize = 5

// ErrAmount reports an invalid amount.
var ErrAmount = errors.New("offline: invalid amount")

// ParseINR converts a rupee string such as "123", "123.4" or "123.45" to
// paise using integer arithmetic only. It rejects empty input, signs,
// spaces, commas, symbols, leading zeros, more than two decimals, zero and
// anything above MaxAmountPaise.
func ParseINR(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("%w: empty", ErrAmount)
	}
	whole, frac, hasDot := strings.Cut(s, ".")
	if whole == "" {
		return 0, fmt.Errorf("%w: %q has no rupee digits", ErrAmount, s)
	}
	if hasDot && (frac == "" || len(frac) > 2) {
		return 0, fmt.Errorf("%w: %q must have one or two decimals", ErrAmount, s)
	}
	for _, part := range []string{whole, frac} {
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return 0, fmt.Errorf("%w: %q contains %q", ErrAmount, s, part[i])
			}
		}
	}
	if len(whole) > 1 && whole[0] == '0' {
		return 0, fmt.Errorf("%w: %q has a leading zero", ErrAmount, s)
	}
	// Check the size before multiplying so nothing can wrap around.
	if len(whole) > 11 {
		return 0, fmt.Errorf("%w: %q exceeds the maximum", ErrAmount, s)
	}
	rupees, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || rupees > MaxAmountPaise/100 {
		return 0, fmt.Errorf("%w: %q exceeds the maximum", ErrAmount, s)
	}
	frac = (frac + "00")[:2]
	paise, _ := strconv.ParseInt(frac, 10, 64)
	total := rupees*100 + paise
	if total > MaxAmountPaise {
		return 0, fmt.Errorf("%w: %q exceeds the maximum", ErrAmount, s)
	}
	if total == 0 {
		return 0, fmt.Errorf("%w: amount must be positive", ErrAmount)
	}
	return total, nil
}

// FormatRupees renders paise as a plain rupee string with two decimals, e.g. "123.45".
func FormatRupees(paise int64) string {
	sign := ""
	if paise < 0 {
		sign, paise = "-", -paise
	}
	return fmt.Sprintf("%s%d.%02d", sign, paise/100, paise%100)
}

// PutAmount writes paise into b[0:5] as an unsigned 40-bit big-endian integer.
func PutAmount(b []byte, paise int64) error {
	if len(b) < AmountSize {
		return fmt.Errorf("%w: buffer shorter than %d bytes", ErrAmount, AmountSize)
	}
	if paise <= 0 || paise > MaxAmountPaise {
		return fmt.Errorf("%w: %d paise out of range", ErrAmount, paise)
	}
	v := uint64(paise)
	for i := AmountSize - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return nil
}

// Amount decodes a 5-byte big-endian amount. Zero is rejected.
func Amount(b []byte) (int64, error) {
	if len(b) < AmountSize {
		return 0, fmt.Errorf("%w: need %d bytes", ErrAmount, AmountSize)
	}
	var v uint64
	for i := 0; i < AmountSize; i++ {
		v = v<<8 | uint64(b[i])
	}
	if v == 0 {
		return 0, fmt.Errorf("%w: zero amount", ErrAmount)
	}
	return int64(v), nil
}
