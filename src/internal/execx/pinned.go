package execx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Pinned is a program the user named by absolute path and sha256: a hook.
// It is not on the tool allow-list, because the user chose it; the pin is
// what makes running it safe to repeat (design ID-06).
type Pinned struct {
	Path    string
	SHA256  string
	Args    []string
	Stdin   []byte
	Env     []string // the only variables the program sees, besides baseEnv's PATH, HOME and temp
	Timeout time.Duration
}

// ErrUnpinned is returned for a program that fails its pin or its checks.
var ErrUnpinned = errors.New("refused to run")

// CheckPinned verifies a pinned program without running it: an absolute path
// to a regular file, not writable by group or others (Unix), whose sha256 is
// the pin. It returns the file's digest.
func CheckPinned(path, pin string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: %w: not an absolute path", path, ErrUnpinned)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w: %v", path, ErrUnpinned, err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s: %w: not a regular file (symlinks are not followed)", path, ErrUnpinned)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("%s: %w: writable by group or others (%v)", path, ErrUnpinned, st.Mode().Perm())
	}
	f, err := os.Open(path) //nolint:gosec // G304: the user's configured hook, checked above
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if pin == "" {
		return sum, fmt.Errorf("%s: %w: no sha256 pin (impr hooks pin prints it)", path, ErrUnpinned)
	}
	if !strings.EqualFold(strings.TrimPrefix(pin, "sha256:"), sum) {
		return sum, fmt.Errorf("%s: %w: sha256 %s is not the pin", path, ErrUnpinned, sum)
	}
	return sum, nil
}

// RunPinned checks the pin and runs the program directly, with no shell, a
// minimal environment, bounded output and a timeout (default 30 s, at most
// 5 minutes).
func RunPinned(ctx context.Context, p Pinned) (Result, error) {
	if _, err := CheckPinned(p.Path, p.SHA256); err != nil {
		return Result{}, err
	}
	d := p.Timeout
	if d <= 0 {
		d = 30 * time.Second
	}
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Path, p.Args...) //nolint:gosec // G204: a pinned program by absolute path, no shell
	base := []string{}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "SystemRoot", "SYSTEMROOT", "USERPROFILE", "LANG":
			base = append(base, kv)
		}
	}
	cmd.Env = append(base, p.Env...)
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(p.Stdin)
	var stdout, stderr limited
	stdout.max, stderr.max = 64<<10, 64<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := Result{Path: p.Path, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%s timed out after %s", filepath.Base(p.Path), d)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}
