package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad: no config.json panics the loader, and one it loads validates.
func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"schema":"imprimatur.config/v1","server":{"listen":"unix"},"approvals":{"enforce":true,"approvers":[{"name":"a","publicKey":"ssh-ed25519 AAAA"}]}}`))
	f.Add([]byte(`{"locked":["hooks"],"hooks":[{"name":"x"}]}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, File), b, 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(dir)
		if err != nil {
			return
		}
		_ = c.Validate()
	})
}
