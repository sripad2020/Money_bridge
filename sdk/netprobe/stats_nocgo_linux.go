//go:build !cgo && linux

package netprobe

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

func goStats(c *net.TCPConn) (*TCPStats, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var info *unix.TCPInfo
	var ierr error
	if err := raw.Control(func(fd uintptr) { info, ierr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil {
		return nil, err
	}
	if ierr != nil {
		return nil, ierr
	}
	return &TCPStats{RTT: time.Duration(info.Rtt) * time.Microsecond, RTTVar: time.Duration(info.Rttvar) * time.Microsecond,
		CongWindow: info.Snd_cwnd, MSS: info.Snd_mss, Retransmitted: info.Total_retrans, BytesInFlight: uint64(info.Unacked)}, nil
}
