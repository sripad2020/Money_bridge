package merchant

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"pstcopay/internal/transport"
)

// DialOptions configures the client.
type DialOptions struct {
	Addr       string
	TLS        *tls.Config
	PoolSize   int    // persistent connections; 1 = a single multiplexed connection
	Congestion string // "bbr", "cubic" or "" (Linux only)
}

// Client is a pool of persistent, multiplexed HTTP/2 connections. Every RPC
// is a stream on one of them. Idempotent calls fail over to the next
// connection when one is unavailable.
type Client struct {
	conns []*grpc.ClientConn
	next  atomic.Uint64
}

// Dial opens the connection pool and starts connecting eagerly.
func Dial(o DialOptions) (*Client, error) {
	if o.PoolSize < 1 {
		o.PoolSize = 1
	}
	c := &Client{}
	for range o.PoolSize {
		cc, err := grpc.NewClient(o.Addr,
			grpc.WithTransportCredentials(credentials.NewTLS(o.TLS)),
			grpc.WithContextDialer(transport.Dialer(o.Congestion)),
			grpc.WithDefaultCallOptions(grpc.CallContentSubtype("json")),
			grpc.WithInitialWindowSize(1<<20),
			grpc.WithInitialConnWindowSize(8<<20),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true,
			}),
		)
		if err != nil {
			c.Close()
			return nil, err
		}
		cc.Connect()
		c.conns = append(c.conns, cc)
	}
	return c, nil
}

// DialCertDir dials using <certDir>/ca.pem and <certDir>/<certName>.pem/-key.pem.
func DialCertDir(addr, certDir, certName string, pool int, cc string) (*Client, error) {
	host := addr
	if h, _, ok := strings.Cut(addr, ":"); ok && h != "" {
		host = h
	}
	cfg, err := transport.ClientTLSConfig(filepath.Join(certDir, certName+".pem"),
		filepath.Join(certDir, certName+"-key.pem"), filepath.Join(certDir, "ca.pem"), host)
	if err != nil {
		return nil, err
	}
	return Dial(DialOptions{Addr: addr, TLS: cfg, PoolSize: pool, Congestion: cc})
}

// Close closes every connection.
func (c *Client) Close() error {
	var errs []error
	for _, cc := range c.conns {
		errs = append(errs, cc.Close())
	}
	return errors.Join(errs...)
}

func (c *Client) invoke(ctx context.Context, method string, req, resp any, idempotent bool) error {
	tries := 1
	if idempotent {
		tries = len(c.conns)
	}
	var err error
	for i := 0; i < tries; i++ {
		cc := c.conns[c.next.Add(1)%uint64(len(c.conns))]
		err = cc.Invoke(ctx, "/"+ServiceName+"/"+method, req, resp)
		if status.Code(err) != codes.Unavailable {
			return err
		}
	}
	return err
}

// CreatePayment submits a payment. It is idempotent by idempotency key, so
// it is safe to retry and to fail over.
func (c *Client) CreatePayment(ctx context.Context, req *CreatePaymentRequest) (*PaymentView, error) {
	out := new(PaymentView)
	return out, c.invoke(ctx, "CreatePayment", req, out, true)
}

// GetPayment reads a payment; with Resolve it runs CSDR on unfinished payments.
func (c *Client) GetPayment(ctx context.Context, req *GetPaymentRequest) (*PaymentView, error) {
	out := new(PaymentView)
	return out, c.invoke(ctx, "GetPayment", req, out, true)
}

// RecoverPayment explicitly runs CSDR.
func (c *Client) RecoverPayment(ctx context.Context, id string) (*PaymentView, error) {
	out := new(PaymentView)
	return out, c.invoke(ctx, "RecoverPayment", &PaymentIDRequest{PaymentID: id}, out, true)
}

// RefundPayment requests a full refund.
func (c *Client) RefundPayment(ctx context.Context, req *RefundRequest) (*PaymentView, error) {
	out := new(PaymentView)
	return out, c.invoke(ctx, "RefundPayment", req, out, true)
}

// GetExecutionGraph returns the verified execution graph.
func (c *Client) GetExecutionGraph(ctx context.Context, id string) (*GraphResponse, error) {
	out := new(GraphResponse)
	return out, c.invoke(ctx, "GetExecutionGraph", &PaymentIDRequest{PaymentID: id}, out, true)
}

// GetTransportState returns the controller's transport view.
func (c *Client) GetTransportState(ctx context.Context) (*TransportResponse, error) {
	out := new(TransportResponse)
	return out, c.invoke(ctx, "GetTransportState", &Empty{}, out, true)
}

// Reconcile runs reconciliation (admin).
func (c *Client) Reconcile(ctx context.Context) (*ReconcileResponse, error) {
	out := new(ReconcileResponse)
	return out, c.invoke(ctx, "Reconcile", &Empty{}, out, false)
}

// VerifyAnchors anchors new events and verifies the anchor log (admin).
func (c *Client) VerifyAnchors(ctx context.Context) (*AnchorsResponse, error) {
	out := new(AnchorsResponse)
	return out, c.invoke(ctx, "VerifyAnchors", &Empty{}, out, false)
}

var watchDesc = &grpc.StreamDesc{StreamName: "WatchPayment", ServerStreams: true}

// WatchPayment streams state updates until the payment is final, fn returns
// false, or ctx ends.
func (c *Client) WatchPayment(ctx context.Context, id string, fn func(*WatchEvent) bool) error {
	cc := c.conns[c.next.Add(1)%uint64(len(c.conns))]
	st, err := cc.NewStream(ctx, watchDesc, "/"+ServiceName+"/WatchPayment")
	if err != nil {
		return err
	}
	if err := st.SendMsg(&PaymentIDRequest{PaymentID: id}); err != nil {
		return err
	}
	if err := st.CloseSend(); err != nil {
		return err
	}
	for {
		ev := new(WatchEvent)
		if err := st.RecvMsg(ev); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if !fn(ev) || ev.Final {
			return nil
		}
	}
}
