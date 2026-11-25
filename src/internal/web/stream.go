package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/server"
)

// maxStreams bounds open event streams, so pages left open cannot use up the
// server's connections.
const maxStreams = 8

// streamLifetime ends a stream after this long; the browser reconnects, and
// the reconnect checks the session again.
const streamLifetime = time.Hour

type streamCount struct {
	mu sync.Mutex
	n  int
}

func (c *streamCount) open() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n >= maxStreams {
		return false
	}
	c.n++
	return true
}

func (c *streamCount) close() {
	c.mu.Lock()
	c.n--
	c.mu.Unlock()
}

// liveEvent is what the events page's stream sends for each event: the id,
// type, subject and time, as JSON. The page sets them as text, so nothing a
// log line holds is ever markup.
type liveEvent struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	Subject string    `json:"subject"`
	Time    time.Time `json:"time"`
}

// eventsStream is GET /events/stream: Server-Sent Events from the event log,
// from its end, filtered by ?type= globs. The log is the one every impr
// process writes, so CLI runs show as well as the UI's own.
func (s *Server) eventsStream(w http.ResponseWriter, r *http.Request) {
	if s.opts.Events.Dir == "" {
		s.renderError(w, r, http.StatusServiceUnavailable, "No event log", "This server has no event log to stream.")
		return
	}
	globs := r.URL.Query()["type"]
	for _, g := range globs {
		if !server.ValidTypeGlob(g) {
			s.renderError(w, r, http.StatusBadRequest, "Not an event type", "The filter is an event type or a glob such as profile.*.")
			return
		}
	}
	cur, err := s.opts.Events.End()
	if err != nil {
		s.renderError(w, r, http.StatusServiceUnavailable, "The event log cannot be read", err.Error())
		return
	}
	if !s.streams.open() {
		w.Header().Set("Retry-After", "30")
		s.renderError(w, r, http.StatusServiceUnavailable, "Too many streams", "Close another events page and reload this one.")
		return
	}
	defer s.streams.close()
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	send := func(format string, args ...any) bool {
		// No WriteTimeout on this server: each write gets its own deadline.
		if err := rc.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := fmt.Fprintf(w, format, args...); err != nil { //nolint:gosec // G705: text/event-stream, and the data is JSON with no line breaks
			return false
		}
		err := rc.Flush()
		return err == nil || errors.Is(err, http.ErrNotSupported)
	}
	if !send(": imprimatur events\nretry: 5000\n\n") {
		return
	}
	poll := s.opts.Poll
	if poll <= 0 {
		poll = time.Second
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	beat := time.NewTicker(15 * time.Second)
	defer beat.Stop()
	end := time.NewTimer(streamLifetime)
	defer end.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-end.C:
			return
		case <-beat.C:
			if !send(": keepalive\n\n") {
				return
			}
		case <-tick.C:
			evs, _, next, err := s.opts.Events.Read(cur)
			if err != nil {
				return
			}
			cur = next
			for _, ev := range evs {
				if !matchAny(globs, ev.Type) {
					continue
				}
				b, err := json.Marshal(liveEvent{ID: ev.ID, Type: ev.Type, Subject: ev.Subject, Time: ev.Time})
				if err != nil || strings.ContainsAny(string(b), "\r\n") {
					continue
				}
				if !send("data: %s\n\n", b) {
					return
				}
			}
		}
	}
}

func matchAny(globs []string, typ string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if events.Matches(g, typ) {
			return true
		}
	}
	return false
}
