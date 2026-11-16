package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
)

// syncWriter is a ResponseWriter a test can read while the handler writes.
type syncWriter struct {
	mu     sync.Mutex
	h      http.Header
	code   int
	buf    bytes.Buffer
	writes chan struct{}
}

func newSyncWriter() *syncWriter {
	return &syncWriter{h: http.Header{}, writes: make(chan struct{}, 64)}
}
func (w *syncWriter) Header() http.Header { return w.h }
func (w *syncWriter) WriteHeader(c int)   { w.mu.Lock(); w.code = c; w.mu.Unlock() }
func (w *syncWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.code == 0 {
		w.code = 200
	}
	return w.buf.Write(b)
}
func (w *syncWriter) Flush() {
	select {
	case w.writes <- struct{}{}:
	default:
	}
}
func (w *syncWriter) body() string { w.mu.Lock(); defer w.mu.Unlock(); return w.buf.String() }

func streamFixture(t *testing.T) (http.Handler, events.Log, events.Env, string, string) {
	t.Helper()
	log := events.Log{Dir: t.TempDir()}
	read, rt := token(t, "events")
	noScope, nt := token(t, "read")
	cfg := config.Config{Schema: config.Schema, Server: config.Server{Roots: []string{filepath.ToSlash(t.TempDir())}, Tokens: []config.Token{rt, nt}}}
	if ps := cfg.Validate(); len(ps) > 0 {
		t.Fatal(ps)
	}
	h := Handler(Options{Config: cfg, Run: (&fakeRun{}).run, StateDir: t.TempDir(), Now: time.Now, Events: log, Poll: 10 * time.Millisecond})
	return h, log, events.Env{InstallID: "test", Now: time.Now, NewID: events.NewID}, read, noScope
}

func emit(t *testing.T, log events.Log, env events.Env, short string) events.Event {
	t.Helper()
	ev, err := env.New(short, "s", map[string]any{"n": 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Write(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// open starts a stream and returns a function that waits for text in it.
func open(t *testing.T, h http.Handler, tok, query, lastID string) (*syncWriter, func(string) bool, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/events/stream"+query, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if lastID != "" {
		r.Header.Set("Last-Event-ID", lastID)
	}
	w := newSyncWriter()
	done := make(chan struct{})
	go func() { h.ServeHTTP(w, r); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	wait := func(s string) bool {
		deadline := time.After(5 * time.Second)
		for !strings.Contains(w.body(), s) {
			select {
			case <-w.writes:
			case <-time.After(20 * time.Millisecond):
			case <-deadline:
				return false
			}
		}
		return true
	}
	return w, wait, cancel
}

func TestStreamSendsNewEventsFiltersAndResumes(t *testing.T) {
	h, log, env, tok, _ := streamFixture(t)
	old := emit(t, log, env, "server.started") // before the stream: not sent

	w, wait, cancel := open(t, h, tok, "?type=signing.*", "")
	if !wait("contract 1") {
		t.Fatalf("no stream preamble: %q", w.body())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	skipped := emit(t, log, env, "server.stopped")
	signed := emit(t, log, env, "signing.run.completed")
	if !wait("id: " + signed.ID) {
		t.Fatalf("the signing event never arrived: %q", w.body())
	}
	body := w.body()
	if !strings.Contains(body, "event: "+events.TypePrefix+"signing.run.completed\ndata: {") {
		t.Fatalf("the message is not an SSE event with the CloudEvent as data: %q", body)
	}
	if strings.Contains(body, old.ID) || strings.Contains(body, skipped.ID) {
		t.Fatalf("an old or filtered event was sent: %q", body)
	}
	cancel()

	// Reconnecting after old resumes from there; the filter is off, so both follow.
	w2, wait2, _ := open(t, h, tok, "", old.ID)
	if !wait2("id: "+skipped.ID) || !wait2("id: "+signed.ID) {
		t.Fatalf("resume did not replay the events after Last-Event-ID: %q", w2.body())
	}
}

func TestStreamRefuses(t *testing.T) {
	h, _, _, tok, noScope := streamFixture(t)
	get := func(tok, query, lastID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/v1/events/stream"+query, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		if lastID != "" {
			r.Header.Set("Last-Event-ID", lastID)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for name, c := range map[string]struct {
		w    *httptest.ResponseRecorder
		want int
	}{
		"no token":        {get("", "", ""), http.StatusUnauthorized},
		"no events scope": {get(noScope, "", ""), http.StatusForbidden},
		"unknown type":    {get(tok, "?type=nope.*", ""), http.StatusBadRequest},
		"unknown resume":  {get(tok, "", "no-such-event"), http.StatusConflict},
		"bad glob":        {get(tok, "?type=a%20b", ""), http.StatusBadRequest},
	} {
		if c.w.Code != c.want {
			t.Errorf("%s: status %d, want %d: %s", name, c.w.Code, c.want, c.w.Body)
		}
	}
}

func TestStreamLimit(t *testing.T) {
	h, _, _, tok, _ := streamFixture(t)
	for i := 0; i < MaxStreams; i++ {
		w, wait, _ := open(t, h, tok, "", "")
		if !wait("contract 1") {
			t.Fatalf("stream %d did not open: %q", i, w.body())
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/events/stream", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("stream %d must be refused with 503 and Retry-After, got %d", MaxStreams+1, w.Code)
	}
}

// ---- OpenAPI -----------------------------------------------------------------

type spec struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"schemas"`
	} `json:"components"`
}

func loadSpec(t *testing.T) spec {
	t.Helper()
	var s spec
	if err := json.Unmarshal(openapiDoc, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// routes reads the patterns Handler registers. net/http's mux cannot list
// them, so this reads server.go itself, and asserts it found them.
func routes(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) (/[^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		out = append(out, strings.ToLower(m[1])+" "+m[2])
	}
	if len(out) < 12 {
		t.Fatalf("found only %d routes in server.go; the pattern no longer matches", len(out))
	}
	sort.Strings(out)
	return out
}

func TestOpenAPIDescribesEveryRouteAndNoOther(t *testing.T) {
	s := loadSpec(t)
	var documented []string
	for path, ops := range s.Paths {
		for method := range ops {
			documented = append(documented, method+" "+path)
		}
	}
	sort.Strings(documented)
	if got := routes(t); !slices.Equal(got, documented) {
		t.Fatalf("routes and the OpenAPI paths differ:\n routes: %v\n spec:   %v", got, documented)
	}
	// Every documented operation reaches a handler (not the mux's 404 or 405).
	h := setup(t, true).h
	for _, op := range documented {
		method, path, _ := strings.Cut(op, " ")
		path = strings.NewReplacer("{name}", "x").Replace(path)
		r := httptest.NewRequest(strings.ToUpper(method), path, strings.NewReader("{}"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed {
			if !strings.Contains(w.Body.String(), `"contract"`) {
				t.Errorf("%s: the mux answered %d", op, w.Code)
			}
		}
	}
}

func TestOpenAPISchemasMatchTheRequestStructs(t *testing.T) {
	s := loadSpec(t)
	for name, v := range map[string]any{"VerifyRequest": VerifyRequest{}, "SignRequest": SignRequest{}, "InboundRequest": InboundRequest{}, "Error": contract.ErrorDoc{}} {
		var fields []string
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			fields = append(fields, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
		}
		var props []string
		for p := range s.Components.Schemas[name].Properties {
			props = append(props, p)
		}
		sort.Strings(fields)
		sort.Strings(props)
		if len(fields) == 0 || !slices.Equal(fields, props) {
			t.Errorf("%s: struct fields %v, schema properties %v", name, fields, props)
		}
	}
}

func TestOpenAPIServedWithoutAToken(t *testing.T) {
	w := httptest.NewRecorder()
	setup(t, false).h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/openapi.json", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"openapi": "3.1.0"`) {
		t.Fatalf("got %d %.80s", w.Code, w.Body)
	}
}
