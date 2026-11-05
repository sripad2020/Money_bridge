//go:build !cgo && !linux

package netprobe

import "net"

func goStats(*net.TCPConn) (*TCPStats, error) { return nil, ErrUnsupported }
