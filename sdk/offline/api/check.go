package api

import (
	"fmt"

	"pstcopay/sdk/validate"
)

// Value rules for every request. The server enforces them after strict type
// decoding; the Go client runs them before sending so mistakes fail fast.

// MaxAmountPaise is the largest amount any request may carry (₹1 crore).
const MaxAmountPaise = 1_00_00_000_00

// Check implements validate.Checker.
func (r *AccountStartRequest) Check() error {
	return validate.All(validate.String("phone", r.Phone, 8, 20), validate.String("name", r.Name, 1, 64))
}

// Check implements validate.Checker.
func (r *AccountVerifyRequest) Check() error {
	return validate.All(validate.String("phone", r.Phone, 8, 20), validate.Digits("otp", r.OTP, 6, 6))
}

// Check implements validate.Checker.
func (r *ChallengeRequest) Check() error {
	return validate.Hex("registration_token", r.RegistrationToken, 64)
}

// Check implements validate.Checker.
func (r *RegisterRequest) Check() error {
	err := validate.All(
		validate.Hex("registration_token", r.RegistrationToken, 64),
		validate.Bytes("challenge", r.Challenge, 32, 32),
		validate.OneOf("algorithm", r.Algorithm, "ed25519", "p256"),
		validate.OneOf("element_kind", r.ElementKind, "software", "android-strongbox", "android-tee", "ios-secure-enclave", "sim-applet"),
		validate.Bytes("public_key", r.PublicKey, 32, 65),
		validate.Bytes("proof", r.Proof, 64, 64),
		validate.OneOf("attestation.format", orNone(r.Attestation.Format), "none", "android-key", "apple-appattest", "sim-x509"),
		validate.Int("attestation.chain", int64(len(r.Attestation.Chain)), 0, 10),
		validate.Bytes("attestation.object", r.Attestation.Object, 0, 64<<10),
		validate.Int("rasp", int64(len(r.RASP)), 0, 50),
		validate.String("model", r.Model, 0, 64),
		validate.String("app_version", r.AppVersion, 0, 32),
	)
	if err != nil {
		return err
	}
	for i, c := range r.Attestation.Chain {
		if err := validate.Bytes(fmt.Sprintf("attestation.chain[%d]", i), c, 64, 16<<10); err != nil {
			return err
		}
	}
	for i, f := range r.RASP {
		if err := validate.All(validate.String(fmt.Sprintf("rasp[%d].check", i), f.Check, 1, 32),
			validate.OneOf(fmt.Sprintf("rasp[%d].severity", i), f.Severity, "info", "warning", "critical"),
			validate.String(fmt.Sprintf("rasp[%d].detail", i), f.Detail, 0, 256)); err != nil {
			return err
		}
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// Check implements validate.Checker.
func (r *DepositRequest) Check() error {
	return validate.Int("amount_paise", r.AmountPaise, 1, MaxAmountPaise)
}

// Check implements validate.Checker.
func (r *ReserveRequest) Check() error {
	return validate.All(
		validate.Int("amount_paise", r.AmountPaise, 0, MaxAmountPaise),
		validate.Int("next_counter", int64(r.NextCounter), 1, 1<<32-1),
		validate.Bytes("chain_head", r.ChainHead, 16, 16),
	)
}

// Check implements validate.Checker.
func (r *SyncRequest) Check() error {
	if err := validate.Int("records", int64(len(r.Records)), 1, 500); err != nil {
		return err
	}
	for i, rec := range r.Records {
		if err := validate.Bytes(fmt.Sprintf("records[%d]", i), rec, 114, 114); err != nil {
			return err
		}
	}
	return validate.Int("rasp", int64(len(r.RASP)), 0, 50)
}

// Check implements validate.Checker.
func (r *AuthNonceRequest) Check() error {
	return validate.OneOf("purpose", r.Purpose, PurposeDeposit, PurposeReserve)
}

// Check implements validate.Checker.
func (r *SMSInbound) Check() error {
	return validate.All(validate.String("from", r.From, 8, 20), validate.Bytes("payload", r.Payload, 114, 114*8))
}
