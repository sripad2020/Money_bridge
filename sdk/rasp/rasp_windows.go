//go:build windows

package rasp

import "golang.org/x/sys/windows"

var procIsDebuggerPresent = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsDebuggerPresent")

func debuggerAttached() (bool, string) {
	if procIsDebuggerPresent.Find() != nil {
		return false, ""
	}
	r, _, _ := procIsDebuggerPresent.Call()
	if r != 0 {
		return true, "IsDebuggerPresent reports a debugger"
	}
	return false, ""
}

func platformRootPaths() []string { return nil }
