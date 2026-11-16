package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
)

// MaxStreams bounds concurrent event streams, so streams cannot use up the
// server's connections.
const MaxStreams = 8

// StreamLifetime closes a stream after this long. The client reconnects with
// Last-Event-ID, which re-checks its token, so a revoked token stops reading
// within this bound once the server reloads its config.
const StreamLifetime = time.Hour

const heartbeat = 15 * time.Second

var typeGlobRe = regexp.MustCompile(`^[a-z0-9.*-]{1,120}$`)

// stream is GET /v1/events/stream: Server-Sent Events from the event log,
// which every impr process writes, so it carries CLI runs as well as API
// ones. Each event is one SSE message: id is the CloudEvent id, event its
// type, data the log line. Without Last-Event-ID it starts at the end of
// the log; with one it resumes just after that event.
func (s *server) stream(w http.ResponseWriter, r *http.Request) {
	if s.o.Events.Dir == "" {
		writeErr(w, http.StatusServiceUnavailable, contract.Unavailable, "this server has no event log")
		return
	}
	globs := r.URL.Query()["type"]
	for _, g := range globs {
		if !typeGlobRe.MatchString(g) || !events.KnownGlob(g) {
			writeErr(w, http.StatusBadRequest, contract.Usage, "type %q matches no event type", g)
			return
		}
	}
	cur, err := s.o.Events.End()
	if id := r.Header.Get("Last-Event-ID"); id != "" && err == nil {
		var ok bool
		if cur, ok, err = s.o.Events.After(id); err == nil && !ok {
			writeErr(w, http.StatusConflict, contract.Usage, "event %q is not in the log; reconnect without Last-Event-ID", id)
			return
		}
	}
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, contract.Unavailable, "the event log cannot be read")
		return
	}
	if !s.openStream() {
		w.Header().Set("Retry-After", "30")
		writeErr(w, http.StatusServiceUnavailable, contract.Unavailable, "%d event streams are open already", MaxStreams)
		return
	}
	defer s.closeStream()

	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(format string, args ...any) bool {
		// The server's WriteTimeout would end a long stream; each write
		// gets its own deadline instead.
		if err := rc.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send(": imprimatur event stream, contract %d\nretry: 5000\n\n", contract.Version) {
		return
	}
	poll := s.o.Poll
	if poll <= 0 {
		poll = time.Second
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	beat := time.NewTicker(heartbeat)
	defer beat.Stop()
	done := time.NewTimer(StreamLifetime)
	defer done.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-done.C:
			return
		case <-beat.C:
			if !send(": keepalive\n\n") {
				return
			}
		case <-tick.C:
			evs, raws, next, err := s.o.Events.Read(cur)
			if err != nil {
				s.logf("server    event stream: %v", err)
				return
			}
			cur = next
			for i, ev := range evs {
				if !matchAny(globs, ev.Type) {
					continue
				}
				if !send("id: %s\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, raws[i]) {
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

func (s *server) openStream() bool {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.streams >= MaxStreams {
		return false
	}
	s.streams++
	return true
}

func (s *server) closeStream() {
	s.streamMu.Lock()
	s.streams--
	s.streamMu.Unlock()
}
