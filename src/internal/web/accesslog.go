package web

import (
	"net/http"
	"time"
)

// statusWriter remembers the status a handler wrote, for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Flush keeps the events stream streaming.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests writes each request to the server's log: a change (any method
// but GET or HEAD) with Log, a page view with Debug. Only the path is written,
// never the query, so a sign-in link's token cannot reach the log.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		logf := s.opts.Debug
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			logf = s.opts.Log
		}
		if logf != nil {
			logf("web       %s %s %d %dms", r.Method, r.URL.Path, sw.status, time.Since(start).Milliseconds())
		}
	})
}
