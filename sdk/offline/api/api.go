// Package api defines the PSTCO-Pay offline HTTP API: paths, JSON bodies and
// device request signing. It is shared by the Go SDK client and the server,
// and documents the wire contract for clients in any other language.
//
// Transport: HTTPS (TLS 1.3, HTTP/2). Bodies are JSON. Binary values are
// standard base64. Device and payee IDs are 16 hex digits.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Paths.
const (
	PathAccountStart  = "/v1/accounts/start"
	PathAccountVerify = "/v1/accounts/verify"
	PathChallenge     = "/v1/devices/challenge"
	PathRegister      = "/v1/devices/register"
	PathCA            = "/v1/ca"
	PathDeposit       = "/v1/wallet/deposit"
	PathWallet        = "/v1/wallet"
	PathReserves      = "/v1/reserves"
	PathSync          = "/v1/sync"
	PathDirectory     = "/v1/directory"
	PathPaymentPrefix = "/v1/offline-payments/" // + {device}/{counter}
	PathSMSInbound    = "/v1/sms/inbound"
	PathAuthNonce     = "/v1/auth/nonce"
	PathSyncJobs      = "/v1/sync/jobs/" // + {id}
)

// Purposes a server nonce can be issued for. Money-moving requests must use a
// server-issued nonce of the matching purpose as their X-Pstco-Nonce.
const (
	PurposeDeposit = "deposit"
	PurposeReserve = "reserve"
)

// AuthNonceRequest asks the server for an unpredictable single-use nonce.
type AuthNonceRequest struct {
	Purpose string `json:"purpose"`
}

// AuthNonceResponse carries a 256-bit server nonce as 64 hex characters.
type AuthNonceResponse struct {
	Nonce            string `json:"nonce"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

// SyncJob is an asynchronous sync: submitted with ?async=1, polled by id.
type SyncJob struct {
	JobID     string       `json:"job_id"`
	Status    string       `json:"status"` // QUEUED | RUNNING | DONE
	Submitted int          `json:"submitted"`
	Results   []SyncResult `json:"results,omitempty"`
}

// Device request authentication headers.
const (
	HeaderDevice      = "X-Pstco-Device"
	HeaderTimestamp   = "X-Pstco-Timestamp"
	HeaderSignature   = "X-Pstco-Signature"
	HeaderNonce       = "X-Pstco-Nonce"
	HeaderIdempotency = "Idempotency-Key"
	HeaderGatewaySig  = "X-Pstco-Gateway-Signature"
	HeaderGatewayTime = "X-Pstco-Gateway-Timestamp"
)

// RequestTag and RegisterTag prefix every message a device signs for the
// API. A secure element must refuse to sign anything else with these keys,
// so an API signature can never be turned into a payment record.
const (
	RequestTag  = "PSTCO-REQ-1\n"
	RegisterTag = "PSTCO-REG-1\n"
)

// RequestMessage is the exact message a device signs to authenticate a
// request. nonce is a fresh random value per request (HeaderNonce), so two
// identical requests in the same second still carry different signatures.
func RequestMessage(method, pathAndQuery string, unix int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(RequestTag + strings.ToUpper(method) + "\n" + pathAndQuery + "\n" +
		strconv.FormatInt(unix, 10) + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
}

// RegisterMessage is the proof of possession a device signs at registration.
func RegisterMessage(challenge []byte, registrationToken string, publicKey []byte) []byte {
	tok := sha256.Sum256([]byte(registrationToken))
	return []byte(RegisterTag + hex.EncodeToString(challenge) + "\n" + hex.EncodeToString(tok[:]) + "\n" +
		hex.EncodeToString(publicKey))
}

// Error is every non-2xx response body.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ------------------------------------------------------------- accounts

// AccountStartRequest begins phone verification; the server sends an OTP by SMS.
type AccountStartRequest struct {
	Phone  string `json:"phone"`
	Name   string `json:"name"`
	Listed bool   `json:"listed"` // appear in the payee directory (shops)
}

// AccountStartResponse reports the OTP was sent. DevOTP is filled only when
// the server runs in development mode.
type AccountStartResponse struct {
	ExpiresInSeconds int    `json:"expires_in_seconds"`
	DevOTP           string `json:"dev_otp,omitempty"`
}

// AccountVerifyRequest confirms the OTP.
type AccountVerifyRequest struct {
	Phone string `json:"phone"`
	OTP   string `json:"otp"`
}

// AccountVerifyResponse returns a single-use registration token.
type AccountVerifyResponse struct {
	AccountID         string `json:"account_id"`
	PayeeID           string `json:"payee_id"`
	RegistrationToken string `json:"registration_token"`
	ExpiresInSeconds  int    `json:"expires_in_seconds"`
}

// --------------------------------------------------------- registration

// ChallengeRequest asks for a single-use registration challenge.
type ChallengeRequest struct {
	RegistrationToken string `json:"registration_token"`
}

// ChallengeResponse carries the challenge to attest and sign.
type ChallengeResponse struct {
	Challenge        []byte `json:"challenge"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

// Attestation is platform evidence that a key lives in secure hardware.
// Format "none" (or an empty format) registers the device with software trust.
type Attestation struct {
	Format string   `json:"format"`           // none | android-key | apple-appattest | sim-x509
	Chain  [][]byte `json:"chain,omitempty"`  // DER certificates, leaf first
	Object []byte   `json:"object,omitempty"` // apple-appattest attestation object (CBOR)
	// Assertion (apple-appattest) is a CBOR {signature, authenticatorData}
	// made by the App Attest key over clientData = challenge || public_key.
	// It binds the Secure Enclave signing key to the attested app instance.
	Assertion []byte `json:"assertion,omitempty"`
}

// RASPFinding is one runtime self-protection observation.
type RASPFinding struct {
	Check    string `json:"check"`
	Severity string `json:"severity"` // info | warning | critical
	Detail   string `json:"detail"`
}

// RegisterRequest registers a device key.
type RegisterRequest struct {
	RegistrationToken string        `json:"registration_token"`
	Challenge         []byte        `json:"challenge"`
	Algorithm         string        `json:"algorithm"`    // ed25519 | p256
	ElementKind       string        `json:"element_kind"` // software | android-strongbox | android-tee | ios-secure-enclave | sim-applet
	PublicKey         []byte        `json:"public_key"`
	Proof             []byte        `json:"proof"` // signature over RegisterMessage
	Attestation       Attestation   `json:"attestation"`
	RASP              []RASPFinding `json:"rasp,omitempty"`
	Model             string        `json:"model,omitempty"`
	AppVersion        string        `json:"app_version,omitempty"`
}

// Limits are the offline limits granted to a device.
type Limits struct {
	PerPaymentPaise int64 `json:"per_payment_paise"`
	MaxReservePaise int64 `json:"max_reserve_paise"`
	ReserveDays     int   `json:"reserve_days"`
}

// RegisterResponse returns the device certificate.
type RegisterResponse struct {
	DeviceID        string `json:"device_id"`
	AccountID       string `json:"account_id"`
	PayeeID         string `json:"payee_id"`
	Trust           string `json:"trust"`
	TrustNote       string `json:"trust_note,omitempty"`
	Certificate     []byte `json:"certificate"`
	CAPublicKey     []byte `json:"ca_public_key"`
	ReceiptKey      []byte `json:"receipt_public_key"`
	Limits          Limits `json:"limits"`
	RevokedDeviceID string `json:"revoked_device_id,omitempty"` // the account's previous device
}

// CAResponse publishes the bank CA key that signs certificates, reserves and directories.
type CAResponse struct {
	PublicKey        []byte `json:"public_key"`
	ReceiptPublicKey []byte `json:"receipt_public_key"`
}

// ------------------------------------------------------------ wallet

// DepositRequest funds the online wallet (simulated bank top-up).
type DepositRequest struct {
	AmountPaise int64 `json:"amount_paise"`
}

// WalletResponse is the account's online view.
type WalletResponse struct {
	AccountID       string          `json:"account_id"`
	PayeeID         string          `json:"payee_id"`
	AvailablePaise  int64           `json:"available_paise"`
	ReservedPaise   int64           `json:"reserved_paise"`
	ActiveReserve   *ReserveSummary `json:"active_reserve,omitempty"`
	DeviceStatus    string          `json:"device_status"`
	PendingInPaise  int64           `json:"pending_incoming_paise"`
	SettledInPaise  int64           `json:"settled_incoming_paise"`
	LastSyncedCount uint32          `json:"last_synced_counter"`
}

// ReserveSummary describes a reserve.
type ReserveSummary struct {
	ReserveID    string `json:"reserve_id"`
	AmountPaise  int64  `json:"amount_paise"`
	SpentPaise   int64  `json:"spent_paise"`
	CounterStart uint32 `json:"counter_start"`
	ExpiresAt    int64  `json:"expires_at"`
	Status       string `json:"status"`
}

// ReserveRequest moves money from the online wallet into a new offline reserve.
// NextCounter and ChainHead prove the device has synced every record it signed.
type ReserveRequest struct {
	AmountPaise int64  `json:"amount_paise"`
	NextCounter uint32 `json:"next_counter"`
	ChainHead   []byte `json:"chain_head"`
}

// ReserveResponse carries the signed reserve instruction for the secure element.
type ReserveResponse struct {
	Instruction []byte         `json:"instruction"`
	Reserve     ReserveSummary `json:"reserve"`
	CarriedOver int64          `json:"carried_over_paise"`
}

// ------------------------------------------------------------ sync

// SyncRequest uploads records: the device's own, or ones it received as payee.
type SyncRequest struct {
	Records [][]byte      `json:"records"`
	RASP    []RASPFinding `json:"rasp,omitempty"`
}

// Record statuses returned by sync.
const (
	StatusAccepted  = "ACCEPTED"  // verified, settlement queued
	StatusSettled   = "SETTLED"   // money moved to the payee
	StatusDuplicate = "DUPLICATE" // already received, nothing new
	StatusRejected  = "REJECTED"  // invalid; see reason
)

// SyncResult is the outcome of one uploaded record. Receipt (98 bytes) is
// the server's signed proof of acceptance; verify it with
// offline.VerifyReceipt and the receipt key from /v1/ca or registration.
type SyncResult struct {
	DeviceID string `json:"device_id"`
	Counter  uint32 `json:"counter"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Receipt  []byte `json:"receipt,omitempty"`
}

// SyncResponse returns one result per record, in request order.
type SyncResponse struct {
	Results []SyncResult `json:"results"`
}

// DirectoryResponse is the signed payee directory and revocation list.
type DirectoryResponse struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// PaymentEvent is one server-signed event of an offline payment.
type PaymentEvent struct {
	Seq       int64             `json:"seq"`
	Stage     string            `json:"stage"`
	Status    string            `json:"status"`
	Signer    string            `json:"signer"`
	Hash      string            `json:"hash"`
	PrevHash  string            `json:"prev_hash"`
	Payload   map[string]string `json:"payload"`
	CreatedAt int64             `json:"created_at"`
}

// PaymentResponse is the server's view of one offline payment.
type PaymentResponse struct {
	DeviceID    string         `json:"device_id"`
	Counter     uint32         `json:"counter"`
	AmountPaise int64          `json:"amount_paise"`
	PayeeID     string         `json:"payee_id"`
	Status      string         `json:"status"`
	Reason      string         `json:"reason,omitempty"`
	Channel     string         `json:"channel"`
	Verified    bool           `json:"graph_verified"`
	Events      []PaymentEvent `json:"events"`
}

// SMSInbound is what an SMS aggregator posts for a message to the short code.
// The body is authenticated with HMAC-SHA256 in HeaderGatewaySig.
type SMSInbound struct {
	From    string `json:"from"`
	Payload []byte `json:"payload"` // the binary SMS: one 114-byte record
}
