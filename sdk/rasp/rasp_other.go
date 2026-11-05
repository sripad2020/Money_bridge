//go:build !linux && !windows && !darwin

package rasp

func debuggerAttached() (bool, string) { return false, "" }

func platformRootPaths() []string { return nil }
