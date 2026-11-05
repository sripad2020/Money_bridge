package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// KDF is the Argon2id cost used to derive keys from the PIN.
type KDF struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// DefaultKDF suits phones: about 0.1 to 0.3 s and 32 MiB.
var DefaultKDF = KDF{Time: 3, MemoryKiB: 32 * 1024, Threads: 2}

// TestKDF is fast and must only be used in tests.
var TestKDF = KDF{Time: 1, MemoryKiB: 64, Threads: 1}

func (k KDF) derive(pin string, salt []byte) []byte {
	return argon2.IDKey([]byte(pin), salt, k.Time, k.MemoryKiB, k.Threads, 32)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func seal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := randomBytes(g.NonceSize())
	return g.Seal(nonce, nonce, plaintext, aad), nil
}

var errOpen = errors.New("wallet: cannot decrypt")

func open(key, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, errOpen
	}
	out, err := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
	if err != nil {
		return nil, errOpen
	}
	return out, nil
}

// writeFileAtomic writes via a synced temporary file and rename, so a crash
// leaves either the old or the new file, never a torn one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("wallet: replace %s: %w", filepath.Base(path), err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func validPIN(pin string) bool {
	if len(pin) < 6 || len(pin) > 32 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
