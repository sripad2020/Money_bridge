package netprobe

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func listen(t *testing.T) (*net.TCPListener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	return ln.(*net.TCPListener), ln.Addr().(*net.TCPAddr).Port
}

func TestProbeReachableAndUnreachable(t *testing.T) {
	t.Logf("implementation: %s (native=%t)", Version(), Native())
	_, port := listen(t)
	ps, err := ProbeTCP(context.Background(), "127.0.0.1", port, 16, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s := Summarize(ps)
	if s.Succeeded != 16 || s.Loss != 0 || s.Max <= 0 && s.Min < 0 {
		t.Fatalf("reachable: %+v %v", s, ps[0].Err)
	}
	// A port with no listener: every probe fails.
	free, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := free.Addr().(*net.TCPAddr).Port
	free.Close()
	ps, err = ProbeTCP(context.Background(), "127.0.0.1", closed, 4, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if s := Summarize(ps); s.Succeeded != 0 || s.Loss != 1 {
		t.Fatalf("closed port: %+v", s)
	}
	if _, err := ProbeTCP(context.Background(), "127.0.0.1", port, 65, time.Second); err == nil {
		t.Fatal("65 probes accepted")
	}
}

func TestTuneAndStats(t *testing.T) {
	_, port := listen(t)
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	if err := Tune(tc, Tuning{NoDelay: true, KeepAlive: 30 * time.Second, SendBuffer: 1 << 16}); err != nil {
		t.Fatalf("tune: %v", err)
	}
	_, _ = tc.Write(make([]byte, 4096))
	st, err := Stats(tc)
	if err == ErrUnsupported {
		t.Skipf("TCP statistics not available here (native=%t)", Native())
	}
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.MSS == 0 {
		t.Fatalf("stats look empty: %+v", st)
	}
	t.Logf("kernel TCP stats: %+v", st)
}
