package winres

import (
	"testing"
)

// FuzzReadResources: no .rsrc section or version block, however malformed,
// panics the reader (impr rules reads the version information of any file
// it is given).
func FuzzReadResources(f *testing.F) {
	if syso, err := Syso("amd64", Info{ProductName: "Acme", FileVersion: "1.2.3"}, CLIManifest, nil); err == nil {
		f.Add(syso[60:], uint32(0)) // the .rsrc section of a real object, at RVA 0
	}
	vi, _ := VersionInfo(Info{ProductName: "Acme", FileVersion: "1"})
	f.Add(vi, uint32(0))
	f.Add([]byte{}, uint32(4096))
	f.Fuzz(func(t *testing.T, b []byte, va uint32) {
		if data, ok := findVersion(b, va); ok {
			walkVersion(data, map[string]string{})
		}
		walkVersion(b, map[string]string{})
	})
}
