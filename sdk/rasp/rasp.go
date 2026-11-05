// Package rasp is runtime application self-protection for wallet apps. It
// inspects the running process and device for signs of attack (debugger,
// root or jailbreak, hooking frameworks, a modified binary) and reports
// findings. The wallet refuses to unlock or pay on a critical finding, and
// the server records reports at registration and sync.
//
// RASP raises the cost of an attack; it is not the trust anchor. The secure
// hardware, the signatures and the server-side reserve limits are.
package rasp

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"pstcopay/sdk/offline/api"
)

// Severities.
const (
	Info     = "info"
	Warning  = "warning"
	Critical = "critical"
)

// Report is the result of one check run.
type Report struct {
	Findings []api.RASPFinding `json:"findings"`
}

// Critical reports whether any finding is critical.
func (r Report) Critical() bool {
	for _, f := range r.Findings {
		if f.Severity == Critical {
			return true
		}
	}
	return false
}

// Guard runs runtime checks.
type Guard interface {
	Check() Report
}

// Config tunes the default guard.
type Config struct {
	// ExpectedBinarySHA256 is the hex SHA-256 of the released app binary.
	// When set, a different running binary is a critical finding.
	ExpectedBinarySHA256 string
	// RootPaths overrides the files whose presence indicates root or jailbreak.
	RootPaths []string
	// HookMarkers overrides the library names that indicate hooking.
	HookMarkers []string
	// Disable lists check names to skip (debugger, root, hooking, integrity).
	Disable []string
}

// DefaultRootPaths covers common Android root and iOS jailbreak artefacts.
var DefaultRootPaths = []string{
	"/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/adb/magisk",
	"/system/app/Superuser.apk", "/system/bin/.ext/.su",
	"/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/bin/bash", "/usr/sbin/sshd", "/etc/apt",
	"/private/var/lib/apt/",
}

// DefaultHookMarkers covers common instrumentation frameworks.
var DefaultHookMarkers = []string{"frida", "gum-js-loop", "xposed", "substrate", "libhooker", "cycript"}

type guard struct {
	cfg      Config
	disabled map[string]bool
}

// New returns the default guard.
func New(cfg Config) Guard {
	if cfg.RootPaths == nil {
		cfg.RootPaths = platformRootPaths()
	}
	if cfg.HookMarkers == nil {
		cfg.HookMarkers = DefaultHookMarkers
	}
	d := map[string]bool{}
	for _, n := range cfg.Disable {
		d[n] = true
	}
	return &guard{cfg: cfg, disabled: d}
}

func (g *guard) Check() Report {
	var r Report
	add := func(check, sev, detail string) {
		r.Findings = append(r.Findings, api.RASPFinding{Check: check, Severity: sev, Detail: detail})
	}
	if !g.disabled["debugger"] {
		if attached, detail := debuggerAttached(); attached {
			add("debugger", Critical, detail)
		}
	}
	if !g.disabled["root"] {
		for _, p := range g.cfg.RootPaths {
			if _, err := os.Stat(p); err == nil {
				add("root", Critical, "found "+p)
				break
			}
		}
	}
	if !g.disabled["hooking"] {
		if m := hookingLibraries(g.cfg.HookMarkers); m != "" {
			add("hooking", Critical, "instrumentation library mapped: "+m)
		}
	}
	if !g.disabled["integrity"] && g.cfg.ExpectedBinarySHA256 != "" {
		sum, err := executableSHA256()
		switch {
		case err != nil:
			add("integrity", Warning, "cannot hash running binary: "+err.Error())
		case !strings.EqualFold(sum, g.cfg.ExpectedBinarySHA256):
			add("integrity", Critical, "running binary differs from the released build")
		}
	}
	return r
}

// hookingLibraries scans the process memory map (Linux and Android).
func hookingLibraries(markers []string) string {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.ToLower(sc.Text())
		for _, m := range markers {
			if strings.Contains(line, m) {
				return m
			}
		}
	}
	return ""
}

func executableSHA256() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Static is a guard that always returns the same findings (tests, or a host
// app that runs its own native RASP and passes the results in).
type Static struct{ Findings []api.RASPFinding }

// Check implements Guard.
func (s Static) Check() Report { return Report{Findings: s.Findings} }
