package events

import "testing"

// W2: Source is SourceFor under the default setting.
func TestSourceIsTheDefault(t *testing.T) {
	if s, ok := SourceFor("sange.sh", "abc"); !ok || Source("abc") != s {
		t.Fatalf("Source %q, SourceFor %q", Source("abc"), s)
	}
}
