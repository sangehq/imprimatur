package backend

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadPESigner: no file, PE or not, panics the signer reader.
func FuzzReadPESigner(f *testing.F) {
	f.Add([]byte("MZ"))
	f.Add(append([]byte("MZ"), make([]byte, 0x40)...))
	f.Add([]byte("\x7fELF"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "x.exe")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = ReadPESigner(p)
	})
}

// FuzzParsePKCS7: no DER panics the signature parser.
func FuzzParsePKCS7(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parsePKCS7(b)
	})
}

// FuzzSSHSigKey: no armored signature panics the key reader.
func FuzzSSHSigKey(f *testing.F) {
	f.Add([]byte("-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n"))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = SSHSigKey(b)
	})
}

// FuzzWindowsName: no raw subject panics the name renderer.
func FuzzWindowsName(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = WindowsName(b)
	})
}
