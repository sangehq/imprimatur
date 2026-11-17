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

// O-168: an error prints its message, details and fix lines; anything that
// is not a contract error is "unavailable".
func TestTextAndCodeOf(t *testing.T) {
	err := New(Usage, "bad %s", "flag").WithDetails("why").WithFix("do this")
	if got := Text(err); got != "impr: bad flag\n  why\n  fix: do this\n" {
		t.Fatalf("Text: %q", got)
	}
	if CodeOf(io.EOF) != Unavailable || CodeOf(nil) != OK || CodeOf(err) != Usage {
		t.Fatal("CodeOf")
	}
	if d := DocOf(err); d.ExitCode != 1 || d.OK || d.Error.Fix[0] != "do this" {
		t.Fatalf("DocOf: %+v", d)
	}
}
