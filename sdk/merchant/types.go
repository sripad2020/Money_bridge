// Package merchant is the PSTCO-Pay gRPC API over HTTP/2 and TLS 1.3 mutual TLS.
//
// Messages use a JSON codec (content-subtype "json") so the service builds
// without protoc. proto/pstco/v1/payment.proto documents the same contract
// for clients that want generated protobuf stubs.
package merchant

import (
	"encoding/json"
	"time"

	"pstcopay/internal/chain"
	"pstcopay/internal/controller"
	"pstcopay/internal/engine"
	"pstcopay/internal/model"
	"pstcopay/sdk/validate"
)

// ServiceName is the fully qualified gRPC service name.
const ServiceName = "pstco.v1.PaymentService"

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func (jsonCodec) Unmarshal(b []byte, v any) error { return validate.DecodeStrict(b, v) }
func (jsonCodec) Name() string                    { return "json" }

// CreatePaymentRequest is a signed merchant payment request.
type CreatePaymentRequest struct {
	MerchantID     string `json:"merchant_id"`
	CustomerID     string `json:"customer_id"`
	IdempotencyKey string `json:"idempotency_key"`
	AmountMinor    int64  `json:"amount_minor"`
	Currency       string `json:"currency"`
	CardToken      string `json:"card_token"`
	ClientTimeMS   int64  `json:"client_time_ms"`
	ExpiresAtMS    int64  `json:"expires_at_ms"`
	DeadlineMS     int64  `json:"deadline_ms"`
	Signature      string `json:"signature"`
}

// Model converts to the domain request.
func (r *CreatePaymentRequest) Model() *model.PaymentRequest {
	return &model.PaymentRequest{
		MerchantID: r.MerchantID, CustomerID: r.CustomerID, IdempotencyKey: r.IdempotencyKey,
		AmountMinor: r.AmountMinor, Currency: r.Currency, CardToken: r.CardToken,
		ClientTime: time.UnixMilli(r.ClientTimeMS), ExpiresAt: time.UnixMilli(r.ExpiresAtMS),
		DeadlineMS: r.DeadlineMS, Signature: r.Signature,
	}
}

// Sign fills the HMAC request signature.
func (r *CreatePaymentRequest) Sign(secret string) {
	r.Signature = model.SignRequest(r.Model(), secret)
}

// PaymentView is the API representation of a payment.
type PaymentView struct {
	PaymentID      string                     `json:"payment_id"`
	MerchantID     string                     `json:"merchant_id"`
	IdempotencyKey string                     `json:"idempotency_key"`
	State          string                     `json:"state"`
	FailureCode    string                     `json:"failure_code,omitempty"`
	FailureReason  string                     `json:"failure_reason,omitempty"`
	AmountMinor    int64                      `json:"amount_minor"`
	Currency       string                     `json:"currency"`
	AuthID         string                     `json:"auth_id,omitempty"`
	CaptureID      string                     `json:"capture_id,omitempty"`
	SettlementID   string                     `json:"settlement_id,omitempty"`
	RefundID       string                     `json:"refund_id,omitempty"`
	RiskScore      float64                    `json:"risk_score"`
	RiskDecision   string                     `json:"risk_decision,omitempty"`
	Attempts       map[string]int             `json:"attempts"`
	Recoveries     int                        `json:"recoveries"`
	StageMS        map[string]float64         `json:"stage_ms"`
	Events         int                        `json:"events"`
	ServerMS       float64                    `json:"server_ms"`
	CreatedAt      string                     `json:"created_at"`
	UpdatedAt      string                     `json:"updated_at"`
	Transport      *controller.TransportState `json:"transport,omitempty"`
}

// Final reports whether the payment needs no further action from the client.
func (v *PaymentView) Final() bool {
	switch model.State(v.State) {
	case model.StateSettlementPending, model.StateSettlementProcessing:
		return true
	}
	return model.State(v.State).Terminal()
}

func newView(p *model.Payment, events []*chain.Event) *PaymentView {
	v := &PaymentView{
		PaymentID: p.ID, MerchantID: p.MerchantID, IdempotencyKey: p.IdempotencyKey, State: string(p.State),
		FailureCode: string(p.FailureCode), FailureReason: p.FailureReason, AmountMinor: p.AmountMinor,
		Currency: p.Currency, AuthID: p.AuthID, CaptureID: p.CaptureID, SettlementID: p.SettlementID,
		RefundID: p.RefundID, RiskScore: p.RiskScore, RiskDecision: p.RiskDecision,
		Attempts: map[string]int{}, StageMS: map[string]float64{}, Events: len(events),
		CreatedAt: p.CreatedAt.Format(time.RFC3339Nano), UpdatedAt: p.UpdatedAt.Format(time.RFC3339Nano),
	}
	for i, ev := range events {
		switch {
		case ev.Stage == model.StageRecovery:
			v.Recoveries++
		case ev.Status == model.EventPending:
			v.Attempts[string(ev.Stage)]++
		case ev.Stage == model.StageValidate || ev.Stage == model.StageAuthenticate || ev.Stage == model.StageRisk:
			v.Attempts[string(ev.Stage)] = max(v.Attempts[string(ev.Stage)], ev.Attempt)
		}
		if i > 0 {
			d := float64(ev.CreatedAt-events[i-1].CreatedAt) / 1e6
			v.StageMS[string(ev.Stage)] += d
		}
	}
	return v
}

// GetPaymentRequest looks a payment up by id or by merchant request key.
// Resolve asks the server to run CSDR on an unfinished payment first.
type GetPaymentRequest struct {
	PaymentID      string `json:"payment_id,omitempty"`
	MerchantID     string `json:"merchant_id,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Resolve        bool   `json:"resolve,omitempty"`
}

// PaymentIDRequest names one payment.
type PaymentIDRequest struct {
	PaymentID string `json:"payment_id"`
}

// RefundRequest asks for a full refund.
type RefundRequest struct {
	PaymentID  string `json:"payment_id"`
	MerchantID string `json:"merchant_id"`
	Reason     string `json:"reason"`
}

// GraphResponse is a payment's verified execution graph.
type GraphResponse struct {
	PaymentID         string            `json:"payment_id"`
	Verified          bool              `json:"verified"`
	VerificationError string            `json:"verification_error,omitempty"`
	Events            []*chain.Event    `json:"events"`
	PublicKeys        map[string]string `json:"public_keys"`
}

// Empty is an empty message.
type Empty struct{}

// TransportResponse is the PSTCO controller's view of the transport.
type TransportResponse struct {
	Transport controller.TransportState     `json:"transport"`
	Ops       map[string]controller.OpStats `json:"ops"`
}

// WatchEvent is one streamed state update.
type WatchEvent struct {
	PaymentID   string `json:"payment_id"`
	State       string `json:"state"`
	FailureCode string `json:"failure_code,omitempty"`
	AtMS        int64  `json:"at_ms"`
	Final       bool   `json:"final"`
}

// ReconcileResponse wraps a reconciliation report.
type ReconcileResponse struct {
	Report *engine.ReconReport `json:"report"`
}

// AnchorsResponse wraps an anchor verification report.
type AnchorsResponse struct {
	Report *engine.AnchorReport `json:"report"`
	Latest *chain.Anchor        `json:"latest_anchor,omitempty"`
}
