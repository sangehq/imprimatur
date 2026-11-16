package events

import (
	"errors"
	"fmt"
)

// Head is a chain's position: how many lines it holds and the hash of the
// last one. Kept off the machine (an audit.head event delivered by a
// webhook), it proves later that no line up to it was rewritten.
type Head struct {
	Hash  string `json:"head"`
	Count int    `json:"count"`
}

// Head returns the log's current head. An empty log has count 0.
func (l Log) Head() (Head, error) {
	var h Head
	err := l.Each(func(_ Event, raw []byte) error {
		h.Count++
		h.Hash = lineHash(raw)
		return nil
	})
	return h, err
}

var errStop = errors.New("stop")

// Matches reports whether line h.Count of the log still hashes to h.Hash,
// so the log's history up to that point is the history that was anchored.
func (l Log) Matches(h Head) error {
	if h.Count < 1 {
		return fmt.Errorf("the anchor names no line")
	}
	n, got := 0, ""
	err := l.Each(func(_ Event, raw []byte) error {
		n++
		if n == h.Count {
			got = lineHash(raw)
			return errStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return err
	}
	if n < h.Count {
		return fmt.Errorf("the log has %d line(s), fewer than the %d anchored: lines were removed", n, h.Count)
	}
	if got != h.Hash {
		return fmt.Errorf("line %d is not the line that was anchored: the log was rewritten", h.Count)
	}
	return nil
}
