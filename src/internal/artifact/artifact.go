// Package artifact reads the build manifest sange's build stage writes
// (sange.build-manifest/v1), resolves its paths safely under the signing root,
// hashes files and tells which platform a file belongs to by its first bytes.
package artifact

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/capped"
	"github.com/sangehq/imprimatur/src/internal/contract"
)

// ManifestSchema identifies the build manifest.
const ManifestSchema = "sange.build-manifest/v1"

// Entry is one built file.
type Entry struct {
	Path   string `json:"path"` // relative to the repository root, slash separated
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the build manifest.
type Manifest struct {
	Schema    string  `json:"schema"`
	Commit    string  `json:"commit"`
	Tree      string  `json:"tree"`
	Version   string  `json:"version"`
	Artifacts []Entry `json:"artifacts"`
}

// Loaded is a manifest with the digest of its file's bytes and its directory.
type Loaded struct {
	Manifest
	Path   string
	Digest string // "sha256:<hex>" of the file as read
	Dir    string
}

var hexSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReadManifest reads and checks a build manifest.
func ReadManifest(path string) (Loaded, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Loaded{}, err
	}
	b, err := capped.ReadFile(abs, capped.Manifest)
	if errors.Is(err, capped.ErrTooLarge) {
		return Loaded{}, contract.Wrap(contract.Usage, err, "the build manifest %s is too large to be one", path)
	}
	if err != nil {
		return Loaded{}, contract.Wrap(contract.Usage, err, "build manifest not found: %s", path).
			WithDetails("--manifest names the build-manifest.json the build stage wrote.")
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Loaded{}, contract.Wrap(contract.Usage, err, "%s is not JSON", path)
	}
	if m.Schema != ManifestSchema {
		return Loaded{}, contract.New(contract.Usage, "%s is not a build manifest (%s)", path, ManifestSchema)
	}
	if len(m.Artifacts) == 0 {
		return Loaded{}, contract.New(contract.Usage, "the build manifest %s lists no artifacts", path)
	}
	seen := map[string]bool{}
	for _, a := range m.Artifacts {
		if !hexSHA.MatchString(strings.ToLower(a.SHA256)) {
			return Loaded{}, contract.New(contract.Usage, "%s: %q is not a sha256 digest", a.Path, a.SHA256)
		}
		if seen[a.Path] {
			return Loaded{}, contract.New(contract.Usage, "%s is listed twice in the build manifest", a.Path)
		}
		// Refused when read, not only when signed: a manifest nothing could
		// sign is not one to approve or record (found by FuzzReadManifest).
		if leavesRoot(a.Path) {
			return Loaded{}, contract.New(contract.Usage, "the build manifest lists %q, which is not a path inside the signing root", a.Path)
		}
		seen[a.Path] = true
	}
	h := sha256.Sum256(b)
	return Loaded{Manifest: m, Path: abs, Digest: "sha256:" + hex.EncodeToString(h[:]), Dir: filepath.Dir(abs)}, nil
}

// leavesRoot reports whether a manifest path is empty, absolute or rooted,
// names a volume, or climbs out with "..".
func leavesRoot(rel string) bool {
	clean := filepath.ToSlash(rel)
	return rel == "" || filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" || strings.HasPrefix(clean, "/") ||
		regexp.MustCompile(`(^|/)\.\.(/|$)`).MatchString(clean)
}

// Resolve turns a manifest path into a file under root. A path that is
// absolute, climbs out with .., or reaches outside root through a symlink is
// refused.
func Resolve(root, rel string) (string, error) {
	clean := filepath.ToSlash(rel)
	if leavesRoot(rel) {
		return "", contract.New(contract.SignFailed, "manifest path %q leaves the signing root", rel)
	}
	full := filepath.Join(root, filepath.FromSlash(clean))
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", contract.Wrap(contract.SignFailed, err, "%s is listed in the build manifest but missing under %s", rel, root)
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	if r, err := filepath.Rel(rootReal, real); err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", contract.New(contract.SignFailed, "%s resolves outside the signing root", rel)
	}
	st, err := os.Stat(real)
	if err != nil || !st.Mode().IsRegular() {
		return "", contract.New(contract.SignFailed, "%s is not a regular file", rel)
	}
	// The resolved path, so a later rename replaces the file, not a link to it.
	return real, nil
}

// SHA256 is the lower-case hex sha256 of a file.
func SHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: an artifact resolved under the signing root
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Kind is the platform a file belongs to.
type Kind string

// Kinds.
const (
	KindWindows Kind = "windows"
	KindMacOS   Kind = "macos"
	KindOther   Kind = "other"
)

var machO = [][]byte{
	{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf}, {0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
	{0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca},
}

var ole = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

// KindOf tells a Windows file (a PE, or an .msi compound file) from a macOS
// one (Mach-O, or a .dmg or .pkg) from anything else, by its first bytes and,
// for installers, its extension.
func KindOf(path string) (Kind, error) {
	f, err := os.Open(path) //nolint:gosec // G304: an artifact resolved under the signing root
	if err != nil {
		return KindOther, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 8)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return KindOther, err
	}
	buf = buf[:n]
	ext := strings.ToLower(filepath.Ext(path))
	switch {
	case len(buf) >= 2 && buf[0] == 'M' && buf[1] == 'Z':
		return KindWindows, nil
	case ext == ".msi" && bytes.HasPrefix(buf, ole):
		return KindWindows, nil
	case ext == ".dmg" || ext == ".pkg":
		return KindMacOS, nil
	}
	if len(buf) >= 4 {
		for _, m := range machO {
			if bytes.Equal(buf[:4], m) {
				return KindMacOS, nil
			}
		}
	}
	return KindOther, nil
}

// RelToRoot renders a path for a record: slash-separated and relative to root
// when it is under it, absolute otherwise.
func RelToRoot(root, path string) string {
	if r, err := filepath.Rel(root, path); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(r)
	}
	return path
}

// Checksums renders "<hex>  <path>\n" lines.
func Checksums(lines [][2]string) []byte {
	var b strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&b, "%s  %s\n", l[0], l[1])
	}
	return []byte(b.String())
}

// ParseChecksums reads "<hex>  <path>" lines (the format Checksums writes, and
// sha256sum's binary-mode "*path"). Blank lines are skipped; anything else
// that is not a 64-hex digest followed by a path is an error, so a tampered
// file cannot hide an entry behind a line impr does not understand.
func ParseChecksums(b []byte) ([][2]string, error) {
	var out [][2]string
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		sum, path, ok := strings.Cut(line, " ")
		path = strings.TrimPrefix(strings.TrimPrefix(path, " "), "*")
		// A path with a control character (a lone \r, a tab, NUL) is no
		// artifact's, and would not survive being written back (found by
		// FuzzParseChecksums).
		// Nor is one that still starts with "*" after the binary-mode marker,
		// or has spaces at either end: each reads back as another path
		// (found by FuzzParseChecksums: "<hash>  **").
		if !ok || !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(sum) || path == "" ||
			strings.ContainsFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) ||
			strings.HasPrefix(path, "*") || strings.TrimSpace(path) != path {
			return nil, fmt.Errorf("line %d is not \"<sha256>  <path>\"", i+1)
		}
		if seen[path] {
			return nil, fmt.Errorf("line %d lists %s twice", i+1, path)
		}
		seen[path] = true
		out = append(out, [2]string{strings.ToLower(sum), path})
	}
	return out, nil
}

// WriteFile writes data to path without following a symlink already at path:
// it writes a temporary file in the same directory and renames it over path,
// so a planted link is replaced rather than written through.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// PEArch is a PE file's machine as a Go architecture name ("386", "amd64",
// "arm", "arm64"), or "" for anything else, including an .msi.
func PEArch(path string) string {
	f, err := pe.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARMNT, pe.IMAGE_FILE_MACHINE_ARM:
		return "arm"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	}
	return ""
}
