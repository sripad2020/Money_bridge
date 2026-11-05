//go:build linux

package rasp

import (
	"bufio"
	"os"
	"strings"
)

// debuggerAttached reads TracerPid from /proc/self/status (Linux and Android).
func debuggerAttached() (bool, string) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false, ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "TracerPid:"); ok {
			v = strings.TrimSpace(v)
			if v != "0" {
				return true, "process is traced by pid " + v
			}
		}
	}
	return false, ""
}

func platformRootPaths() []string {
	// On a general Linux host /bin/bash and /etc/apt are normal, so only the
	// Android root artefacts apply.
	var out []string
	for _, p := range DefaultRootPaths {
		if strings.HasPrefix(p, "/system") || strings.HasPrefix(p, "/sbin/su") || strings.HasPrefix(p, "/su/") || strings.HasPrefix(p, "/data/adb") {
			out = append(out, p)
		}
	}
	return out
}
