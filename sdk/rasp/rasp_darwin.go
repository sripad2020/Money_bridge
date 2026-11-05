//go:build darwin

package rasp

import (
	"os"

	"golang.org/x/sys/unix"
)

const pTraced = 0x00000800

// debuggerAttached checks the P_TRACED flag (macOS and iOS).
func debuggerAttached() (bool, string) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return false, ""
	}
	if kp.Proc.P_flag&pTraced != 0 {
		return true, "process is being traced"
	}
	return false, ""
}

func platformRootPaths() []string { return DefaultRootPaths }
