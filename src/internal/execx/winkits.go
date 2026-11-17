package execx

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// kitsBin is where the Windows SDK puts signtool: one folder per SDK
// version, then one per architecture.
func kitsBin() string {
	base := os.Getenv("ProgramFiles(x86)")
	if base == "" {
		return ""
	}
	return filepath.Join(base, "Windows Kits", "10", "bin")
}

// signtoolInKits finds signtool.exe under root (Windows Kits\10\bin): the
// host's architecture first, then x64 (which runs emulated on ARM64), each
// at the newest SDK version by number (O-130, O-197). "" when there is none.
func signtoolInKits(root, goarch string) string {
	if root == "" {
		return ""
	}
	host := map[string]string{"amd64": "x64", "arm64": "arm64", "386": "x86"}[goarch]
	vers, _ := os.ReadDir(root)
	names := make([]string, 0, len(vers))
	for _, v := range vers {
		if v.IsDir() && numericVersion(v.Name()) != nil {
			names = append(names, v.Name())
		}
	}
	slices.SortFunc(names, func(a, b string) int { return slices.Compare(numericVersion(b), numericVersion(a)) })
	archs := []string{"x64"}
	if host != "" && host != "x64" {
		archs = []string{host, "x64"}
	}
	for _, arch := range archs {
		for _, v := range names {
			p := filepath.Join(root, v, arch, "signtool.exe")
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p
			}
		}
	}
	return ""
}

// numericVersion is a dotted version as numbers, or nil if it is not one.
func numericVersion(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil
		}
		out = append(out, n)
	}
	return out
}
