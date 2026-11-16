package webhook

import (
	"context"

	"net/http"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/events"
)

// FuzzVerify: no headers or body panic the verifier, and nothing verifies
// against a key that did not sign it.
func FuzzVerify(f *testing.F) {
	f.Add("msg_1", "1700000000", "v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=", []byte(`{"a":1}`))
	f.Add("", "", "", []byte{})
	f.Add("id", "-1", "v1a,AAAA v1,", []byte("x"))
	key := []byte("an unguessable fuzz key, 32 bytes")
	f.Fuzz(func(t *testing.T, id, ts, sig string, body []byte) {
		h := http.Header{}
		h.Set("webhook-id", id)
		h.Set("webhook-timestamp", ts)
		h.Set("webhook-signature", sig)
		if _, err := Verify(h, body, [][]byte{key}, time.Unix(1700000000, 0), 5*time.Minute); err == nil {
			t.Fatalf("an unsigned delivery verified: %q %q %q", id, ts, sig)
		}
	})
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"":                              0,
		"120":                           2 * time.Minute,
		"-5":                            0,
		"999999":                        24 * time.Hour,
		"Mon, 16 Nov 2026 12:05:00 GMT": 5 * time.Minute,
		"Mon, 16 Nov 2026 11:00:00 GMT": 0,
		"soon":                          0,
	} {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

type goneTransport struct{}

func (goneTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusGone, Body: http.NoBody, Header: http.Header{}}, nil
}

func TestADeadDeliveryIsReported(t *testing.T) {
	var dead []Delivery
	o := Outbox{Dir: t.TempDir(), Now: time.Now, Client: func(bool) *http.Client { return &http.Client{Transport: goneTransport{}} },
		Dead: func(d Delivery) { dead = append(dead, d) }}
	env := events.Env{InstallID: "test", Now: time.Now, NewID: events.NewID}
	ev, err := env.New("signing.run.completed", "s", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	s := Subscription{Name: "gone", URL: "http://127.0.0.1:9/hook", Keys: [][]byte{[]byte("an unguessable test key, 32 bytes")}, AllowPrivate: true}
	if err := o.Enqueue(context.Background(), s, ev); err != nil {
		t.Fatalf("a dead delivery is filed, not an error: %v", err)
	}
	if len(dead) != 1 || dead[0].EventID != ev.ID || dead[0].LastStatus != http.StatusGone {
		t.Fatalf("dead: %+v", dead)
	}
}
