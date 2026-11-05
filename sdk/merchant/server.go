package merchant

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"pstcopay/internal/controller"
	"pstcopay/internal/engine"
	"pstcopay/internal/model"
)

func init() { encoding.RegisterCodec(jsonCodec{}) }

// RPCMetrics records per-RPC latency.
type RPCMetrics interface {
	ObserveRPC(method, code string, d time.Duration)
}

// ServerOptions configures the API server.
type ServerOptions struct {
	// GatewayCN is the certificate CN of a trusted gateway (Envoy). Requests
	// from it carry the merchant identity in x-forwarded-client-cert.
	GatewayCN string
	// AdminCN may call reconciliation and anchor verification.
	AdminCN string
	// MaxConcurrentStreams bounds HTTP/2 streams per connection (backpressure).
	MaxConcurrentStreams uint32
}

// Server implements the PaymentService.
type Server struct {
	eng  *engine.Engine
	ctl  *controller.Controller
	met  RPCMetrics
	opts ServerOptions
}

// NewServer creates the service.
func NewServer(eng *engine.Engine, met RPCMetrics, opts ServerOptions) *Server {
	if opts.MaxConcurrentStreams == 0 {
		opts.MaxConcurrentStreams = 1000
	}
	return &Server{eng: eng, ctl: eng.Controller(), met: met, opts: opts}
}

type principalKey struct{}

// GRPCServer builds a gRPC server with TLS 1.3 mTLS credentials, HTTP/2 flow
// control and keepalive tuned for long-lived multiplexed connections.
func (s *Server) GRPCServer(tlsCfg *tls.Config) *grpc.Server {
	g := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.MaxConcurrentStreams(s.opts.MaxConcurrentStreams),
		grpc.InitialWindowSize(1<<20),
		grpc.InitialConnWindowSize(8<<20),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: 30 * time.Second, Timeout: 10 * time.Second, MaxConnectionIdle: 15 * time.Minute,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
		grpc.ChainUnaryInterceptor(s.unaryInterceptor),
		grpc.ChainStreamInterceptor(s.streamInterceptor),
	)
	g.RegisterService(&serviceDesc, s)
	hs := health.NewServer()
	hs.SetServingStatus(ServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(g, hs)
	return g
}

// --------------------------------------------------------------- identity

// principalFrom extracts the verified mTLS identity of the caller.
func (s *Server) principalFrom(ctx context.Context) (string, error) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := pr.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "TLS required")
	}
	if ti.State.Version != tls.VersionTLS13 {
		return "", status.Error(codes.Unauthenticated, "TLS 1.3 required")
	}
	if len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "verified client certificate required")
	}
	cn := ti.State.VerifiedChains[0][0].Subject.CommonName
	if s.opts.GatewayCN != "" && cn == s.opts.GatewayCN {
		md, _ := metadata.FromIncomingContext(ctx)
		for _, v := range md.Get("x-forwarded-client-cert") {
			if sub := xfccSubjectCN(v); sub != "" {
				return sub, nil
			}
		}
		return "", status.Error(codes.Unauthenticated, "gateway request without forwarded client certificate")
	}
	return cn, nil
}

// xfccSubjectCN extracts the CN from the last element of an Envoy
// x-forwarded-client-cert header (the client closest to the gateway).
func xfccSubjectCN(v string) string {
	elems := splitOutsideQuotes(v, ',')
	if len(elems) == 0 {
		return ""
	}
	for _, kv := range splitOutsideQuotes(elems[len(elems)-1], ';') {
		k, val, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || !strings.EqualFold(k, "Subject") {
			continue
		}
		val = strings.Trim(val, `"`)
		for _, rdn := range strings.Split(val, ",") {
			if name, cn, ok := strings.Cut(strings.TrimSpace(rdn), "="); ok && strings.EqualFold(name, "CN") {
				return cn
			}
		}
	}
	return ""
}

func splitOutsideQuotes(s string, sep rune) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case r == sep && !quoted:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func principal(ctx context.Context) string {
	p, _ := ctx.Value(principalKey{}).(string)
	return p
}

func (s *Server) unaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (resp any, err error) {
	// A panic in one handler must not take down the payment server.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("merchant api panic", "method", info.FullMethod, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			resp, err = nil, status.Error(codes.Internal, "internal error")
		}
	}()
	start := time.Now()
	s.ctl.StreamStarted()
	defer s.ctl.StreamEnded()
	p, err := s.principalFrom(ctx)
	if err == nil {
		resp, err = h(context.WithValue(ctx, principalKey{}, p), req)
	}
	if s.met != nil {
		s.met.ObserveRPC(methodName(info.FullMethod), status.Code(err).String(), time.Since(start))
	}
	return resp, err
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

func (s *Server) streamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("merchant api panic", "method", info.FullMethod, "panic", fmt.Sprint(r))
			err = status.Error(codes.Internal, "internal error")
		}
	}()
	start := time.Now()
	s.ctl.StreamStarted()
	defer s.ctl.StreamEnded()
	p, perr := s.principalFrom(ss.Context())
	err = perr
	if err == nil {
		err = h(srv, &wrappedStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), principalKey{}, p)})
	}
	if s.met != nil {
		s.met.ObserveRPC(methodName(info.FullMethod), status.Code(err).String(), time.Since(start))
	}
	return err
}

func methodName(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 {
		return full[i+1:]
	}
	return full
}

// toStatus maps engine errors to gRPC status codes.
func toStatus(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, engine.ErrInvalidRequest):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, engine.ErrIdempotencyConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, engine.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, engine.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, engine.ErrNotRefundable):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, engine.ErrBusy):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, controller.ErrOverloaded), errors.Is(err, controller.ErrDeadlineTooShort):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	}
	// Never echo internal error text (database, paths) to callers.
	slog.Error("merchant api internal error", "err", err)
	return status.Error(codes.Internal, "internal error")
}

// authorizeFor checks that the caller's identity owns the merchant.
func (s *Server) authorizeFor(ctx context.Context, merchantID string) error {
	p := principal(ctx)
	if s.opts.AdminCN != "" && p == s.opts.AdminCN {
		return nil
	}
	m, err := s.eng.Merchant(ctx, merchantID)
	if err != nil || m.Principal != p {
		return status.Error(codes.PermissionDenied, "caller may not access this merchant's payments")
	}
	return nil
}

func (s *Server) requireAdmin(ctx context.Context) error {
	if s.opts.AdminCN == "" || principal(ctx) != s.opts.AdminCN {
		return status.Error(codes.PermissionDenied, "admin identity required")
	}
	return nil
}

func (s *Server) view(ctx context.Context, p *model.Payment, start time.Time) (*PaymentView, error) {
	evs, err := s.eng.Events(ctx, p.ID)
	if err != nil {
		return nil, toStatus(err)
	}
	v := newView(p, evs)
	v.ServerMS = float64(time.Since(start).Microseconds()) / 1000
	t := s.ctl.Transport()
	v.Transport = &t
	return v, nil
}

// ---------------------------------------------------------------- methods

func (s *Server) createPayment(ctx context.Context, req *CreatePaymentRequest) (any, error) {
	start := time.Now()
	p, err := s.eng.Process(ctx, req.Model(), principal(ctx))
	if err != nil {
		if p == nil {
			return nil, toStatus(err)
		}
	}
	return s.view(ctx, p, start)
}

func (s *Server) getPayment(ctx context.Context, req *GetPaymentRequest) (any, error) {
	start := time.Now()
	var p *model.Payment
	var err error
	if req.PaymentID != "" {
		p, err = s.eng.GetPayment(ctx, req.PaymentID)
	} else {
		p, err = s.eng.GetPaymentByIdempotency(ctx, req.MerchantID, req.IdempotencyKey)
	}
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.authorizeFor(ctx, p.MerchantID); err != nil {
		return nil, err
	}
	if req.Resolve && !p.State.Terminal() {
		if p, err = s.eng.Recover(ctx, p.ID); err != nil {
			return nil, toStatus(err)
		}
	}
	return s.view(ctx, p, start)
}

func (s *Server) recoverPayment(ctx context.Context, req *PaymentIDRequest) (any, error) {
	start := time.Now()
	p, err := s.eng.GetPayment(ctx, req.PaymentID)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.authorizeFor(ctx, p.MerchantID); err != nil {
		return nil, err
	}
	if p, err = s.eng.Recover(ctx, p.ID); err != nil {
		return nil, toStatus(err)
	}
	return s.view(ctx, p, start)
}

func (s *Server) refundPayment(ctx context.Context, req *RefundRequest) (any, error) {
	start := time.Now()
	p, err := s.eng.Refund(ctx, req.PaymentID, req.MerchantID, principal(ctx), req.Reason)
	if err != nil && p == nil {
		return nil, toStatus(err)
	}
	if err != nil {
		return nil, toStatus(err)
	}
	return s.view(ctx, p, start)
}

func (s *Server) executionGraph(ctx context.Context, req *PaymentIDRequest) (any, error) {
	p, err := s.eng.GetPayment(ctx, req.PaymentID)
	if err != nil {
		return nil, toStatus(err)
	}
	if err := s.authorizeFor(ctx, p.MerchantID); err != nil {
		return nil, err
	}
	evs, err := s.eng.Events(ctx, p.ID)
	if err != nil {
		return nil, toStatus(err)
	}
	resp := &GraphResponse{PaymentID: p.ID, Events: evs, Verified: true, PublicKeys: s.eng.PublicKeys()}
	if err := s.eng.VerifyPayment(ctx, p.ID); err != nil {
		resp.Verified, resp.VerificationError = false, err.Error()
	}
	return resp, nil
}

func (s *Server) transportState(context.Context, *Empty) (any, error) {
	return &TransportResponse{Transport: s.ctl.Transport(), Ops: s.ctl.Ops()}, nil
}

func (s *Server) reconcile(ctx context.Context, _ *Empty) (any, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	rep, err := s.eng.Reconcile(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	return &ReconcileResponse{Report: rep}, nil
}

func (s *Server) verifyAnchors(ctx context.Context, _ *Empty) (any, error) {
	if err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	a, err := s.eng.AnchorOnce(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	rep, err := s.eng.VerifyAnchors(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	return &AnchorsResponse{Report: rep, Latest: a}, nil
}

func (s *Server) watchPayment(req *PaymentIDRequest, stream grpc.ServerStream) error {
	ctx := stream.Context()
	p, err := s.eng.GetPayment(ctx, req.PaymentID)
	if err != nil {
		return toStatus(err)
	}
	if err := s.authorizeFor(ctx, p.MerchantID); err != nil {
		return err
	}
	updates, cancel := s.eng.Subscribe(p.ID)
	defer cancel()
	// Re-read after subscribing so no transition is missed.
	if p, err = s.eng.GetPayment(ctx, p.ID); err != nil {
		return toStatus(err)
	}
	send := func(st model.State, fc model.FailureCode, at time.Time) (bool, error) {
		final := st.Terminal()
		err := stream.SendMsg(&WatchEvent{PaymentID: p.ID, State: string(st), FailureCode: string(fc),
			AtMS: at.UnixMilli(), Final: final})
		return final, err
	}
	if done, err := send(p.State, p.FailureCode, p.UpdatedAt); err != nil || done {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-updates:
			if !ok {
				return nil
			}
			if done, err := send(u.State, u.FailureCode, u.At); err != nil || done {
				return err
			}
		}
	}
}

// --------------------------------------------------------- service desc

type paymentService interface{ isPaymentService() }

func (*Server) isPaymentService() {}

func unary[Req any](name string, fn func(s *Server, ctx context.Context, req *Req) (any, error)) grpc.MethodDesc {
	return grpc.MethodDesc{
		MethodName: name,
		Handler: func(srv any, ctx context.Context, dec func(any) error, ic grpc.UnaryServerInterceptor) (any, error) {
			req := new(Req)
			if err := dec(req); err != nil {
				return nil, status.Error(codes.InvalidArgument, err.Error())
			}
			s := srv.(*Server)
			if ic == nil {
				return fn(s, ctx, req)
			}
			info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + ServiceName + "/" + name}
			return ic(ctx, req, info, func(ctx context.Context, r any) (any, error) { return fn(s, ctx, r.(*Req)) })
		},
	}
}

var serviceDesc = grpc.ServiceDesc{
	ServiceName: ServiceName,
	HandlerType: (*paymentService)(nil),
	Methods: []grpc.MethodDesc{
		unary("CreatePayment", (*Server).createPayment),
		unary("GetPayment", (*Server).getPayment),
		unary("RecoverPayment", (*Server).recoverPayment),
		unary("RefundPayment", (*Server).refundPayment),
		unary("GetExecutionGraph", (*Server).executionGraph),
		unary("GetTransportState", (*Server).transportState),
		unary("Reconcile", (*Server).reconcile),
		unary("VerifyAnchors", (*Server).verifyAnchors),
	},
	Streams: []grpc.StreamDesc{{
		StreamName:    "WatchPayment",
		ServerStreams: true,
		Handler: func(srv any, stream grpc.ServerStream) error {
			req := new(PaymentIDRequest)
			if err := stream.RecvMsg(req); err != nil {
				return err
			}
			return srv.(*Server).watchPayment(req, stream)
		},
	}},
	Metadata: "pstco/v1/payment.proto",
}
