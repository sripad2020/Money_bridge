// Package netprobe exposes PSTCO-Pay's network operations: concurrent TCP
// reachability and latency probes, socket tuning and kernel TCP statistics.
//
// Built with cgo (CGO_ENABLED=1) it runs the C library in native/pstconet,
// which also reads TCP statistics on Windows (SIO_TCP_INFO). Without cgo it
// falls back to pure Go, so the SDK never requires a C compiler.
package netprobe

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
)

// ErrUnsupported means the OS or build cannot perform the operation.
var ErrUnsupported = errors.New("netprobe: not supported on this platform or build")

// MaxProbes is the most concurrent probes per call.
const MaxProbes = 64

// Probe is the outcome of one TCP handshake attempt.
type Probe struct {
	Index int
	RTT   time.Duration
	Err   error
}

// Tuning configures a socket.
type Tuning struct {
	NoDelay       bool
	KeepAlive     time.Duration
	SendBuffer    int
	ReceiveBuffer int
	Congestion    string // Linux only: "bbr", "cubic"
}

// TCPStats are kernel TCP statistics for a connection.
type TCPStats struct {
	RTT           time.Duration
	MinRTT        time.Duration
	RTTVar        time.Duration
	CongWindow    uint32
	MSS           uint32
	Retransmitted uint32
	BytesInFlight uint64
}

// Summary condenses a probe run.
type Summary struct {
	Sent, Succeeded  int
	Loss             float64 // fraction of probes that failed
	Min, Median, Max time.Duration
}

// Summarize computes loss and latency percentiles.
func Summarize(ps []Probe) Summary {
	s := Summary{Sent: len(ps)}
	var rtts []time.Duration
	for _, p := range ps {
		if p.Err == nil {
			rtts = append(rtts, p.RTT)
		}
	}
	s.Succeeded = len(rtts)
	if s.Sent > 0 {
		s.Loss = float64(s.Sent-s.Succeeded) / float64(s.Sent)
	}
	if len(rtts) > 0 {
		slices.Sort(rtts)
		s.Min, s.Median, s.Max = rtts[0], rtts[len(rtts)/2], rtts[len(rtts)-1]
	}
	return s
}

// ProbeTCP opens count concurrent TCP connections to host:port and times each
// handshake. With cgo this is one C call multiplexing non-blocking sockets.
func ProbeTCP(ctx context.Context, host string, port, count int, timeout time.Duration) ([]Probe, error) {
	if count < 1 || count > MaxProbes || port < 1 || port > 65535 || timeout <= 0 {
		return nil, errors.New("netprobe: count must be 1..64, port 1..65535, timeout positive")
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < timeout {
		timeout = time.Until(dl)
	}
	return probe(ctx, host, port, count, timeout)
}

// goProbe is the pure-Go implementation: one goroutine per handshake.
func goProbe(ctx context.Context, host string, port, count int, timeout time.Duration) ([]Probe, error) {
	out := make([]Probe, count)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			start := time.Now()
			c, err := d.DialContext(ctx, "tcp", addr)
			out[i] = Probe{Index: i, RTT: time.Since(start), Err: err}
			if err == nil {
				c.Close()
			}
		}()
	}
	wg.Wait()
	return out, nil
}

// Tune applies socket options to a TCP connection.
func Tune(c *net.TCPConn, t Tuning) error { return tune(c, t) }

func goTune(c *net.TCPConn, t Tuning) error {
	if t.NoDelay {
		if err := c.SetNoDelay(true); err != nil {
			return err
		}
	}
	if t.KeepAlive > 0 {
		if err := c.SetKeepAlive(true); err != nil {
			return err
		}
		if err := c.SetKeepAlivePeriod(t.KeepAlive); err != nil {
			return err
		}
	}
	if t.SendBuffer > 0 {
		if err := c.SetWriteBuffer(t.SendBuffer); err != nil {
			return err
		}
	}
	if t.ReceiveBuffer > 0 {
		if err := c.SetReadBuffer(t.ReceiveBuffer); err != nil {
			return err
		}
	}
	if t.Congestion != "" {
		return ErrUnsupported
	}
	return nil
}

// Stats reads kernel TCP statistics for a connection.
func Stats(c *net.TCPConn) (*TCPStats, error) { return stats(c) }
