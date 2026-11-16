package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Cursor is a position in the log: a month file and a byte offset in it.
// The zero Cursor is the start of the log.
type Cursor struct {
	File   string // base name, YYYY-MM.jsonl
	Offset int64
}

// MaxRead bounds how much one Read call takes from the log.
const MaxRead = 1 << 20

// End is the cursor after the last complete line, so a reader sees only what
// is written from now on.
func (l Log) End() (Cursor, error) {
	fs, err := l.files()
	if err != nil || len(fs) == 0 {
		return Cursor{}, err
	}
	last := fs[len(fs)-1]
	b, err := os.ReadFile(last) //nolint:gosec // G304: impr's own log
	if err != nil {
		return Cursor{}, err
	}
	return Cursor{File: filepath.Base(last), Offset: int64(bytes.LastIndexByte(b, '\n') + 1)}, nil
}

// After is the cursor just past the event with this id, and whether it was
// found. A reconnecting stream resumes from it (SSE Last-Event-ID).
func (l Log) After(id string) (Cursor, bool, error) {
	fs, err := l.files()
	if err != nil {
		return Cursor{}, false, err
	}
	for _, name := range fs {
		b, err := os.ReadFile(name) //nolint:gosec // G304: impr's own log
		if err != nil {
			return Cursor{}, false, err
		}
		off := 0
		for off < len(b) {
			i := bytes.IndexByte(b[off:], '\n')
			if i < 0 {
				break
			}
			var ev struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(b[off:off+i], &ev) == nil && ev.ID == id {
				return Cursor{File: filepath.Base(name), Offset: int64(off + i + 1)}, true, nil
			}
			off += i + 1
		}
	}
	return Cursor{}, false, nil
}

// Read returns the complete event lines written after c, oldest first, and
// the cursor after them. A line still being written is left for the next
// call. It moves on to later month files once the current one is read.
func (l Log) Read(c Cursor) ([]Event, [][]byte, Cursor, error) {
	fs, err := l.files()
	if err != nil {
		return nil, nil, c, err
	}
	var evs []Event
	var raws [][]byte
	budget := int64(MaxRead)
	for _, name := range fs {
		base := filepath.Base(name)
		if c.File != "" && base < c.File {
			continue
		}
		if base != c.File {
			c = Cursor{File: base}
		}
		f, err := os.Open(name) //nolint:gosec // G304: impr's own log
		if err != nil {
			return evs, raws, c, err
		}
		if _, err := f.Seek(c.Offset, io.SeekStart); err != nil {
			_ = f.Close()
			return evs, raws, c, err
		}
		b, err := io.ReadAll(io.LimitReader(f, budget))
		_ = f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return evs, raws, c, err
		}
		end := bytes.LastIndexByte(b, '\n') + 1
		for _, line := range bytes.Split(b[:end], []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var ev Event
			if err := json.Unmarshal(line, &ev); err != nil {
				return evs, raws, c, err
			}
			evs = append(evs, ev)
			raws = append(raws, append([]byte(nil), line...))
		}
		c.Offset += int64(end)
		budget -= int64(end)
		if budget <= 0 || int64(end) < int64(len(b)) {
			break // the budget is spent, or a partial line waits in this file
		}
	}
	return evs, raws, c, nil
}
