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
	defer func() { _ = f.Close() }()
	_, err = f.Write(append(line, '\n'))
	return err
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
	b, err := os.ReadFile(fs[len(fs)-1])
	if err != nil {
		return "", err
	}
	b = bytes.TrimRight(b, "\n")
	if len(b) == 0 {
		return "", nil
	}
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
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
	return n, err
}

// Matches reports whether a type matches a glob over full or short type
// names ("signing.*", "sh.sange.imprimatur.cert.*", "*").
func Matches(glob, typ string) bool {
	short := strings.TrimPrefix(typ, TypePrefix)
	for _, t := range []string{typ, short} {
		if ok, _ := filepath.Match(glob, t); ok {
			return true
		}
		if strings.HasSuffix(glob, ".*") && strings.HasPrefix(t, strings.TrimSuffix(glob, "*")) {
			return true
		}
	}
	return false
}
