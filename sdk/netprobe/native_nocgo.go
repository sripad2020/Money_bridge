//go:build !cgo

package netprobe

import (
	"context"
	"net"
	"time"
)

// Native reports whether the C library is linked in.
func Native() bool { return false }

// Version returns the implementation in use.
func Version() string { return "pure Go (build with CGO_ENABLED=1 for the C library)" }

func probe(ctx context.Context, host string, port, count int, timeout time.Duration) ([]Probe, error) {
	return goProbe(ctx, host, port, count, timeout)
}

func tune(c *net.TCPConn, t Tuning) error { return goTune(c, t) }

func stats(c *net.TCPConn) (*TCPStats, error) { return goStats(c) }
