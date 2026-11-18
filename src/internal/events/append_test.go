package events

import (
	"os"
	"path/filepath"
	"testing"
)

// An append reads the end of the newest month file, not the whole file: the
// previous line's hash costs one line however long the log is. Measured on
// the Windows devbox before this, 200 appends by 8 writers took 49 s.
func TestLastLineReadsOnlyTheEnd(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "2026-11.jsonl")
	f, err := os.Create(name) //nolint:gosec // G304: a test file
	if err != nil {
		t.Fatal(err)
	}
	const size = 32 << 20 // a long month, sparse on disk
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("\n{\"first\":1}\n{\"last\":2}\n\n"), size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	line, read, err := lastLine(name)
	if err != nil || string(line) != `{"last":2}` {
		t.Fatalf("last line %q, %v", line, err)
	}
	if read > 64<<10 {
		t.Fatalf("read %d bytes of a %d-byte file to find its last line", read, size)
	}
	// A file holding one line, without a final newline, and an empty one.
	for body, want := range map[string]string{`{"only":1}`: `{"only":1}`, "": "", "\n\n": ""} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if line, _, err := lastLine(name); err != nil || string(line) != want {
			t.Errorf("%q: last line %q, %v", body, line, err)
		}
	}
}
