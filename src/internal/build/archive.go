package build

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

// ArchiveDir is where Archive writes, under build/ (the estate layout:
// archives only on demand).
const ArchiveDir = "archives"

// archiveTime is every archive entry's time, so the same files make the same
// archive bytes.
var archiveTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// universal makes build/macos/{binary}_macos_universal from the darwin/amd64
// and darwin/arm64 builds with lipo (O-145), when both were built. It
// returns the new artifact's path, or "" when there is nothing to join.
func (b Builder) universal(ctx context.Context, outRoot, binary string, built map[Target]string) (string, error) {
	amd, arm := built[Target{GOOS: "darwin", GOARCH: "amd64"}], built[Target{GOOS: "darwin", GOARCH: "arm64"}]
	if amd == "" || arm == "" {
		return "", nil
	}
	out := filepath.Join(outRoot, "macos", binary+"_macos_universal")
	r, err := b.Runner.Run(ctx, execx.Cmd{Tool: "lipo", Args: []string{"-create", "-output", out, amd, arm}})
	if err != nil {
		b.logf("archives  no macOS universal binary: lipo is not available here (%v)", err)
		return "", nil
	}
	if r.ExitCode != 0 {
		return "", contract.New(contract.Usage, "lipo could not join the macOS binaries").WithDetails(strings.TrimSpace(r.Output()))
	}
	return out, nil
}

// Archive packs each binary of the build manifest at manifestPath, as it is on
// disk now (signed, after impr release), into build/archives/: a .zip for a
// Windows binary and a .tar.gz otherwise, named like the binary without .exe.
// Each holds the binary under its own name plus the repository's LICENSE and
// README.md when they exist, and checksums.txt lists every archive by its
// bare name (ID-12).
func Archive(repoRoot string, m Manifest) ([]string, error) {
	dir := filepath.Join(repoRoot, "build", ArchiveDir)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: build output others read
		return nil, err
	}
	var extras []string
	for _, f := range []string{"LICENSE", "README.md"} {
		if st, err := os.Stat(filepath.Join(repoRoot, f)); err == nil && st.Mode().IsRegular() {
			extras = append(extras, f)
		}
	}
	var names, lines []string
	for _, a := range m.Artifacts {
		src := filepath.Join(repoRoot, filepath.FromSlash(a.Path))
		base := filepath.Base(src)
		files := []string{src}
		for _, e := range extras {
			files = append(files, filepath.Join(repoRoot, e))
		}
		var data []byte
		var err error
		name := strings.TrimSuffix(base, ".exe")
		if strings.HasSuffix(base, ".exe") {
			name += ".zip"
			data, err = zipOf(files)
		} else {
			name += ".tar.gz"
			data, err = tarGzOf(files)
		}
		if err != nil {
			return nil, err
		}
		if err := writeAtomic(filepath.Join(dir, name), data); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		names = append(names, name)
		lines = append(lines, hex.EncodeToString(sum[:])+"  "+name)
	}
	sort.Strings(lines)
	if err := writeAtomic(filepath.Join(dir, "checksums.txt"), []byte(strings.Join(lines, "\n")+"\n")); err != nil {
		return nil, err
	}
	return names, nil
}

func tarGzOf(files []string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // G304: a file of this build
		if err != nil {
			return nil, err
		}
		mode := int64(0o644)
		if i == 0 {
			mode = 0o755 // the binary
		}
		if err := tw.WriteHeader(&tar.Header{Name: filepath.Base(f), Mode: mode, Size: int64(len(b)), ModTime: archiveTime, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func zipOf(files []string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		src, err := os.Open(f) //nolint:gosec // G304: a file of this build
		if err != nil {
			return nil, err
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: filepath.Base(f), Method: zip.Deflate, Modified: archiveTime})
		if err == nil {
			_, err = io.Copy(w, src)
		}
		_ = src.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
