package contract

import (
	"errors"
	"io"
	"testing"
)

// W2: every code has a name, and a wrapped error keeps its cause.
func TestCodeStringAndUnwrap(t *testing.T) {
	for _, c := range []Code{OK, Usage, Skipped, SignFailed, VerifyFailed, Unavailable} {
		if c.String() == "" {
			t.Errorf("code %d has no name", c)
		}
	}
	if err := Wrap(Unavailable, io.EOF, "read"); !errors.Is(err, io.EOF) {
		t.Fatal("Wrap lost its cause")
	}
}
