package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sangehq/imprimatur/src/internal/events"
)

// Subscription is one outbound receiver.
type Subscription struct {
	Name  string
	URL   string
	Types []string // event type globs; empty means every internal-class type
	Keys  [][]byte // current key first; a previous one during rotation
	// AllowPrivate permits a loopback, private or link-local target, and
	// plain http to loopback. Off by default (SSRF).
	AllowPrivate bool
}

// Wants reports whether the subscription receives an event. Local-class
// events never leave the machine.
func (s Subscription) Wants(ev events.Event) bool {
	if ev.Class == events.ClassLocal {
		return false
	}
	if len(s.Types) == 0 {
		return true
	}
	for _, g := range s.Types {
		if events.Matches(g, ev.Type) {
			return true
		}
	}
	return false
}

// MaxBody is the largest event impr sends.
const MaxBody = 256 << 10

// CheckURL refuses what a subscription may never target: anything but https
// (http only to loopback, and only with AllowPrivate), userinfo in the URL,
// and a fragment.
func CheckURL(raw string, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.Fragment != "" || u.Host == "" {
		return nil, errors.New("a webhook URL has a host, and no user info or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip, err := netip.ParseAddr(u.Hostname())
		if !allowPrivate || (u.Hostname() != "localhost" && (err != nil || !ip.IsLoopback())) {
			return nil, errors.New("a webhook URL is https (http only to loopback, with allowPrivate)")
		}
	default:
		return nil, errors.New("a webhook URL is https")
	}
	return u, nil
}

// blocked reports addresses a webhook may not reach without AllowPrivate:
// loopback, private, link-local (cloud metadata lives there), multicast,
// unspecified, and the IPv4-mapped forms of all of them.
func blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(ip) // carrier-grade NAT
}

// Client is an HTTP client for one subscription. The dialer checks the
// address it actually connects to (after DNS), so a name that resolves to a
// private address is refused even if it looked public; redirects are never
// followed, and the timeout is 15 s.
func Client(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		if !allowPrivate && blocked(ip) {
			return fmt.Errorf("webhook target %s is a private or local address", ip)
		}
		return nil
	}}
	tr := &http.Transport{DialContext: d.DialContext, Proxy: nil, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second, MaxIdleConns: 4}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Delivery is one pending or finished send, stored in the outbox.
type Delivery struct {
	Subscription string          `json:"subscription"`
	EventID      string          `json:"eventId"`
	EventType    string          `json:"eventType"`
	Body         json.RawMessage `json:"body"` // the exact bytes sent and signed
	Attempts     int             `json:"attempts"`
	FirstTry     time.Time       `json:"firstTry"`
	NextTry      time.Time       `json:"nextTry"`
	LastStatus   int             `json:"lastStatus,omitempty"`
	LastError    string          `json:"lastError,omitempty"`
	KeyIDs       []string        `json:"keyIds,omitempty"`
}

// Backoff is the retry schedule after each failed attempt; after the last,
// the delivery moves to the dead letter.
var Backoff = []time.Duration{0, 5 * time.Second, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 5 * time.Hour, 10 * time.Hour, 10 * time.Hour}

// Outbox stores deliveries under <state>/outbox/{pending,dead,done}, 0600 in
// 0700 dirs, one file per subscription and event.
type Outbox struct {
	Dir    string
	Now    func() time.Time
	Client func(allowPrivate bool) *http.Client
	Warn   func(format string, args ...any)
}

func (o Outbox) path(state string, d Delivery) string {
	return filepath.Join(o.Dir, state, d.Subscription+"--"+d.EventID+".json")
}

func (o Outbox) save(state string, d Delivery) error {
	if err := os.MkdirAll(filepath.Join(o.Dir, state), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	return os.WriteFile(o.path(state, d), b, 0o600)
}

// Delivered reports whether the subscription's receiver has acknowledged an
// event (its delivery is under done/).
func (o Outbox) Delivered(subscription, eventID string) bool {
	_, err := os.Stat(o.path("done", Delivery{Subscription: subscription, EventID: eventID}))
	return err == nil
}

// Enqueue stores a delivery for an event and tries it once now.
func (o Outbox) Enqueue(ctx context.Context, s Subscription, ev events.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if len(body) > MaxBody {
		return fmt.Errorf("event %s is %d bytes, over the %d-byte webhook limit", ev.ID, len(body), MaxBody)
	}
	now := o.Now()
	d := Delivery{Subscription: s.Name, EventID: ev.ID, EventType: ev.Type, Body: body, FirstTry: now, NextTry: now}
	if err := o.save("pending", d); err != nil {
		return err
	}
	return o.attempt(ctx, s, d)
}

// attempt sends once and files the delivery as done, pending (with the next
// try) or dead.
func (o Outbox) attempt(ctx context.Context, s Subscription, d Delivery) error {
	u, err := CheckURL(s.URL, s.AllowPrivate)
	if err == nil {
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(d.Body))
		if err == nil {
			req.Header.Set("Content-Type", "application/cloudevents+json; charset=utf-8")
			req.Header.Set("User-Agent", "imprimatur-webhooks/1 (+https://sange.sh/)")
			SetHeaders(req.Header, s.Keys, d.EventID, o.Now(), d.Body)
			var resp *http.Response
			resp, err = o.Client(s.AllowPrivate).Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
				_ = resp.Body.Close()
				d.LastStatus = resp.StatusCode
				if resp.StatusCode < 200 || resp.StatusCode > 299 {
					err = fmt.Errorf("receiver answered %d", resp.StatusCode)
				}
			}
		}
	}
	d.Attempts++
	for _, k := range s.Keys {
		d.KeyIDs = append(d.KeyIDs, KeyID(k))
	}
	_ = os.Remove(o.path("pending", d))
	if err == nil {
		d.LastError = ""
		return o.save("done", d)
	}
	d.LastError = err.Error()
	if d.LastStatus == http.StatusGone || d.Attempts >= len(Backoff) {
		o.warn("webhooks  %s: %s is dead after %d attempt(s): %v", s.Name, d.EventID, d.Attempts, err)
		return o.save("dead", d)
	}
	d.NextTry = o.Now().Add(Backoff[d.Attempts])
	if d.LastStatus == http.StatusTooManyRequests || d.LastStatus == http.StatusServiceUnavailable {
		d.NextTry = d.NextTry.Add(Backoff[d.Attempts]) // back off harder when the receiver asks
	}
	o.warn("webhooks  %s: %s not delivered (attempt %d): %v", s.Name, d.EventID, d.Attempts, err)
	return o.save("pending", d)
}

// List returns the deliveries in one state, oldest first.
func (o Outbox) List(state string) ([]Delivery, error) {
	m, err := filepath.Glob(filepath.Join(o.Dir, state, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []Delivery
	for _, p := range m {
		b, err := os.ReadFile(p) //nolint:gosec // G304: impr's own outbox
		if err != nil {
			return nil, err
		}
		var d Delivery
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstTry.Before(out[j].FirstTry) })
	return out, nil
}

// Retry sends every pending delivery whose next try is due (force: all of
// them), and returns how many it sent and how many succeeded.
func (o Outbox) Retry(ctx context.Context, subs map[string]Subscription, force bool) (tried, ok int, err error) {
	ds, err := o.List("pending")
	if err != nil {
		return 0, 0, err
	}
	for _, d := range ds {
		s, known := subs[d.Subscription]
		if !known || (!force && d.NextTry.After(o.Now())) {
			continue
		}
		tried++
		if e := o.attempt(ctx, s, d); e == nil {
			if _, err := os.Stat(o.path("done", d)); err == nil {
				ok++
			}
		}
	}
	return tried, ok, nil
}

func (o Outbox) warn(format string, args ...any) {
	if o.Warn != nil {
		o.Warn(format, args...)
	}
}

// Sink is the events.Sink that enqueues an event for every subscription that
// wants it. A failed delivery stays in the outbox; it never fails the command.
type Sink struct {
	Outbox Outbox
	Subs   []Subscription
}

// Write enqueues and tries the event once per subscription.
func (k Sink) Write(ctx context.Context, ev events.Event) error {
	var errs []string
	for _, s := range k.Subs {
		if !s.Wants(ev) {
			continue
		}
		if err := k.Outbox.Enqueue(ctx, s, ev); err != nil {
			errs = append(errs, s.Name+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
