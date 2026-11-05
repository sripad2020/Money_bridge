//go:build cgo

package netprobe

/*
#cgo CFLAGS: -I${SRCDIR}/../../native/pstconet -O2
#cgo windows LDFLAGS: -lws2_32
#include <stdlib.h>
#include "pstconet.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"
)

// Native reports whether the C library is linked in.
func Native() bool { return true }

// Version returns the C library version.
func Version() string { return C.GoString(C.pstco_version()) }

func cerr(rc C.int) error {
	switch rc {
	case C.PSTCO_OK:
		return nil
	case C.PSTCO_EUNSUPPORTED:
		return ErrUnsupported
	case C.PSTCO_EINVAL:
		return errors.New("netprobe: invalid argument")
	case C.PSTCO_ERESOLVE:
		return errors.New("netprobe: cannot resolve host")
	case C.PSTCO_ETIMEOUT:
		return errors.New("netprobe: handshake timed out")
	case C.PSTCO_ECONNECT:
		return errors.New("netprobe: connection refused or unreachable")
	}
	return fmt.Errorf("netprobe: system error %d", int(rc))
}

func probe(ctx context.Context, host string, port, count int, timeout time.Duration) ([]Probe, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ch := C.CString(host)
	defer C.free(unsafe.Pointer(ch))
	rtts := make([]C.int64_t, count)
	errs := make([]C.int, count)
	ms := C.int(timeout.Milliseconds())
	if ms < 1 {
		ms = 1
	}
	rc := C.pstco_probe_many(ch, C.int(port), C.int(count), ms, &rtts[0], &errs[0])
	if rc < 0 {
		return nil, cerr(rc)
	}
	out := make([]Probe, count)
	for i := range count {
		out[i] = Probe{Index: i, RTT: time.Duration(rtts[i]) * time.Microsecond, Err: cerr(errs[i])}
	}
	return out, nil
}

func withFD(c *net.TCPConn, fn func(fd uintptr) C.int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var rc C.int
	if err := raw.Control(func(fd uintptr) { rc = fn(fd) }); err != nil {
		return err
	}
	return cerr(rc)
}

func tune(c *net.TCPConn, t Tuning) error {
	var cc *C.char
	if t.Congestion != "" {
		cc = C.CString(t.Congestion)
		defer C.free(unsafe.Pointer(cc))
	}
	nd := C.int(0)
	if t.NoDelay {
		nd = 1
	}
	ct := C.pstco_tuning{nodelay: nd, keepalive_secs: C.int(t.KeepAlive / time.Second),
		sndbuf: C.int(t.SendBuffer), rcvbuf: C.int(t.ReceiveBuffer), congestion: cc}
	return withFD(c, func(fd uintptr) C.int { return C.pstco_tune_socket(C.intptr_t(fd), &ct) })
}

func stats(c *net.TCPConn) (*TCPStats, error) {
	var s C.pstco_tcp_stats
	if err := withFD(c, func(fd uintptr) C.int { return C.pstco_read_tcp_stats(C.intptr_t(fd), &s) }); err != nil {
		return nil, err
	}
	return &TCPStats{RTT: time.Duration(s.rtt_us) * time.Microsecond, MinRTT: time.Duration(s.min_rtt_us) * time.Microsecond,
		RTTVar: time.Duration(s.rttvar_us) * time.Microsecond, CongWindow: uint32(s.snd_cwnd), MSS: uint32(s.mss),
		Retransmitted: uint32(s.total_retrans), BytesInFlight: uint64(s.bytes_in_flight)}, nil
}

var _ = goProbe // the pure-Go path stays compiled for comparison tests
var _ = goTune
