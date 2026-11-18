package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/events"
)

func testEvent(t *testing.T, short string) events.Event {
	t.Helper()
	ev, err := events.Env{Now: time.Now, NewID: events.NewID, InstallID: "0123456789abcdef"}.New(short, "s", map[string]any{"x": 1})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestDeliverSignsRetriesAndDeadLetters(t *testing.T) {
	sec, _ := NewSecret()
	key, _ := DecodeSecret(sec)
	var status atomic.Int32
	status.Store(500)
	var verified atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if _, err := Verify(r.Header, body, [][]byte{key}, time.Now(), 0); err == nil &&
			r.Header.Get("Content-Type") == "application/cloudevents+json; charset=utf-8" {
			verified.Add(1)
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()

	ob := Outbox{Dir: t.TempDir(), Now: time.Now, Client: Client}
	sub := Subscription{Name: "ci", URL: srv.URL, Keys: [][]byte{key}, AllowPrivate: true, Types: []string{"signing.*"}}
	sink := Sink{Outbox: ob, Subs: []Subscription{sub}}

	// A type the subscription does not want, and a local-class event, are not sent.
	_ = sink.Write(context.Background(), testEvent(t, "verification.run.completed"))
	_ = sink.Write(context.Background(), testEvent(t, "config.changed"))
	if verified.Load() != 0 {
		t.Fatal("an unwanted event was sent")
	}

	// A 500 leaves the delivery pending with a later next try.
	if err := sink.Write(context.Background(), testEvent(t, "signing.run.completed")); err != nil {
		t.Fatal(err)
	}
	p, _ := ob.List("pending")
	if len(p) != 1 || p[0].Attempts != 1 || !p[0].NextTry.After(time.Now()) || p[0].LastStatus != 500 {
		t.Fatalf("pending: %+v", p)
	}
	// Not due yet: a normal retry sends nothing; a forced one does, and a 200 completes it.
	if tried, _, _ := ob.Retry(context.Background(), map[string]Subscription{"ci": sub}, false); tried != 0 {
		t.Fatalf("retried %d before due", tried)
	}
	status.Store(200)
	if tried, ok, err := ob.Retry(context.Background(), map[string]Subscription{"ci": sub}, true); tried != 1 || ok != 1 || err != nil {
		t.Fatalf("forced retry: %d %d %v", tried, ok, err)
	}
	if d, _ := ob.List("done"); len(d) != 1 || verified.Load() != 2 {
		t.Fatalf("done %d, verified %d", len(d), verified.Load())
	}

	// 410 Gone goes straight to the dead letter.
	status.Store(410)
	_ = sink.Write(context.Background(), testEvent(t, "signing.run.failed"))
	if d, _ := ob.List("dead"); len(d) != 1 {
		t.Fatalf("dead: %+v", d)
	}
}

func TestSSRFGuards(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	// The dialer refuses a loopback target unless the subscription allows it,
	// whatever the URL looks like.
	if _, err := Client(false).Get(srv.URL); err == nil {
		t.Fatal("a loopback target was reached without allowPrivate")
	}
	if resp, err := Client(true).Get(srv.URL); err != nil {
		t.Fatalf("allowPrivate: %v", err)
	} else {
		_ = resp.Body.Close()
	}
	withUserInfo := (&url.URL{Scheme: "https", Host: "example.com", Path: "/", User: url.UserPassword("u", events.NewID())}).String()
	for raw, allow := range map[string]bool{
		"http://example.com/h":   true,  // http to a non-loopback host
		withUserInfo:             false, // user info
		"ftp://example.com/":     false,
		"http://127.0.0.1/h":     false, // loopback http without allowPrivate
		"https://example.com/#f": false,
	} {
		if _, err := CheckURL(raw, allow); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
	if _, err := CheckURL("https://hooks.example.com/impr", false); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"10.0.0.1", "169.254.169.254", "192.168.1.1", "::1", "fe80::1", "::ffff:127.0.0.1", "100.64.0.1", "0.0.0.0"} {
		if !blocked(netip.MustParseAddr(a)) {
			t.Errorf("%s is not blocked", a)
		}
	}
	// Security review I-09: an IPv4 address embedded in NAT64, 6to4 or an
	// IPv4-compatible address is checked as itself, and reserved IPv4 ranges
	// and Teredo are blocked outright.
	for _, a := range []string{"64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1", "2002:a9fe:a9fe::1", "2002:7f00:1::", "::7f00:1",
		"0.1.2.3", "198.18.0.1", "198.19.255.255", "240.0.0.1", "255.255.255.255", "192.0.0.8", "2001:0:4136:e378::1"} {
		if !blocked(netip.MustParseAddr(a)) {
			t.Errorf("%s is not blocked", a)
		}
	}
	for _, a := range []string{"93.184.216.34", "64:ff9b::5db8:d822", "2002:5db8:d822::1", "2606:4700::1111"} {
		if blocked(netip.MustParseAddr(a)) {
			t.Errorf("public address %s is blocked", a)
		}
	}
}
