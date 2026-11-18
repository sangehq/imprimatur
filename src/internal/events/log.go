package events

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Log is the append-only event log: one JSON line per event in
// <state>/events/YYYY-MM.jsonl, files 0600 in a 0700 dir. Each event carries
// imprprev, the sha256 of the line before it (across month files), so
// `impr events verify` detects an edited, removed or reordered line.
type Log struct {
	Dir string // <state>/events
}

// Write appends one event, chaining it to the last line written.
func (l Log) Write(_ context.Context, ev Event) error {
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return err
	}
	unlock, err := l.lock()
	if err != nil {
		return err
	}
	defer unlock()
	prev, err := l.lastHash()
	if err != nil {
		return err
	}
	ev.Prev = prev
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	name := filepath.Join(l.Dir, ev.Time.UTC().Format("2006-01")+".jsonl")
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // G304: impr's own log
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// The head file holds the last line's hash, so an edit to the newest
	// line (which no later line chains to) is detected too.
	return writeHead(filepath.Join(l.Dir, "head"), lineHash(line))
}

func writeHead(path, hash string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hash+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// files lists the month files in order.
func (l Log) files() ([]string, error) {
	m, err := filepath.Glob(filepath.Join(l.Dir, "[0-9][0-9][0-9][0-9]-[0-9][0-9].jsonl"))
	sort.Strings(m)
	return m, err
}

func lineHash(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func (l Log) lastHash() (string, error) {
	fs, err := l.files()
	if err != nil || len(fs) == 0 {
		return "", err
	}
	b, _, err := lastLine(fs[len(fs)-1])
	if err != nil || len(b) == 0 {
		return "", err
	}
	return lineHash(b), nil
}

// Each calls fn for every event in order, stopping at the first error.
func (l Log) Each(fn func(ev Event, raw []byte) error) error {
	fs, err := l.files()
	if err != nil {
		return err
	}
	for _, name := range fs {
		f, err := os.Open(name) //nolint:gosec // G304: impr's own log
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 4<<20)
		for sc.Scan() {
			raw := append([]byte{}, sc.Bytes()...)
			if len(bytes.TrimSpace(raw)) == 0 {
				continue
			}
			var ev Event
			if err := json.Unmarshal(raw, &ev); err != nil {
				_ = f.Close()
				return fmt.Errorf("%s: a line is not an event: %w", filepath.Base(name), err)
			}
			if err := fn(ev, raw); err != nil {
				_ = f.Close()
				return err
			}
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	return nil
}

// Verify walks the chain and returns how many events it checked, or the
// first break.
func (l Log) Verify() (int, error) {
	n, prev := 0, ""
	err := l.Each(func(ev Event, raw []byte) error {
		n++
		if ev.Prev != prev {
			return fmt.Errorf("event %d (%s, %s) does not follow the one before it: the log was edited", n, ev.ID, ev.Type)
		}
		prev = lineHash(raw)
		return nil
	})
	if err != nil || n == 0 {
		return n, err
	}
	head, herr := os.ReadFile(filepath.Join(l.Dir, "head")) //nolint:gosec // G304: impr's own log
	if herr != nil {
		return n, fmt.Errorf("the log has no head record, so its newest line cannot be checked")
	}
	if strings.TrimSpace(string(head)) != prev {
		return n, fmt.Errorf("the newest line (event %d) is not the one last written: the log was edited", n)
	}
	return n, nil
}

// Matches reports whether a type matches a glob over full or short type
// names ("signing.*", "com.simtabi.sange.imprimatur.cert.*", "*"). The type
// may carry either prefix, and the glob is tried against both full forms, so
// a filter written with the sh.sange.imprimatur prefix (deprecated, see
// LegacyTypePrefix) keeps selecting the same events.
func Matches(glob, typ string) bool {
	short := ShortType(typ)
	for _, t := range []string{TypePrefix + short, LegacyTypePrefix + short, short} {
		if ok, _ := filepath.Match(glob, t); ok {
			return true
		}
		if strings.HasSuffix(glob, ".*") && strings.HasPrefix(t, strings.TrimSuffix(glob, "*")) {
			return true
		}
	}
	return false
}
