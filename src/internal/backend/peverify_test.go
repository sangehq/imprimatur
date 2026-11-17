package backend

import (
	"crypto/x509/pkix"
	"encoding/binary"
	"os"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/testpe"
)

// O-173: a signed PE file is checked against its own signature before rules
// are made from it, so a file changed after signing is never allow-listed.
func TestVerifyAuthenticode(t *testing.T) {
	sub := pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}}
	ca := testpe.NewIntermediate(t, "Acme CA", testpe.NewCA(t, "Root"))
	fresh := func() (string, []byte) {
		p, _ := testpe.Signed(t, t.TempDir(), "tool.exe", sub, ca)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return p, b
	}
	p, _ := fresh()
	if err := VerifyAuthenticode(p); err != nil {
		t.Fatalf("an intact file: %v", err)
	}
	opt := func(b []byte) int { return int(binary.LittleEndian.Uint32(b[0x3c:])) + 24 }
	for _, c := range []struct {
		name   string
		change func(b []byte)
		want   error
	}{
		{"a byte of the DOS stub", func(b []byte) { b[10] ^= 1 }, ErrTampered},
		{"a byte of the optional header", func(b []byte) { b[opt(b)+8] ^= 1 }, ErrTampered},
		{"the checksum, which the hash leaves out", func(b []byte) { b[opt(b)+64] ^= 1 }, nil},
		{"a byte of the signature value", func(b []byte) { b[len(b)-3] ^= 1 }, ErrTampered},
	} {
		p, b := fresh()
		c.change(b)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		err := VerifyAuthenticode(p)
		switch {
		case c.want == nil && err != nil:
			t.Errorf("%s: got %v, want it to verify", c.name, err)
		case c.want != nil && err == nil:
			t.Errorf("%s: verified, want %v", c.name, c.want)
		}
	}
}
