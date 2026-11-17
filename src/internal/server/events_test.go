package server

import "testing"

// W2: GET /v1/events runs impr events tail, with a bounded limit.
func TestEventsEndpoint(t *testing.T) {
	f := setup(t, false)
	if r := do(f.h, "GET", "/v1/events?limit=5", f.read, "", nil); r.Code != 200 || f.run.last() != "events tail --limit=5 --json" {
		t.Fatalf("events: %d %q", r.Code, f.run.last())
	}
	for _, bad := range []string{"0", "1001", "x"} {
		if r := do(f.h, "GET", "/v1/events?limit="+bad, f.read, "", nil); r.Code != 400 {
			t.Errorf("limit=%s: %d, want 400", bad, r.Code)
		}
	}
	if r := do(f.h, "GET", "/v1/events", f.ver, "", nil); r.Code != 403 {
		t.Errorf("a verify token read events: %d", r.Code)
	}
}
