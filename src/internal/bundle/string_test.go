package bundle

import (
	"strings"
	"testing"
)

// W2: a bundle names its owner and profile count in messages.
func TestBundleString(t *testing.T) {
	if s := (Bundle{Owner: "acme"}).String(); !strings.Contains(s, "acme bundle (0 profiles)") {
		t.Fatal(s)
	}
}
