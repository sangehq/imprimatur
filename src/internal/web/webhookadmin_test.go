package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/config"
)

// Adding or removing a webhook in the web UI needs server.allowAdmin, as over
// the API, unless server.web.webhookAdmin is owner. The forms stay, disabled,
// with the reason and the fix; test and retry change no configuration and
// stay allowed.
func TestWebhookWritesNeedAllowAdmin(t *testing.T) {
	p := newPagesWith(t, false, nil)
	add := url.Values{"name": {"ci2"}, "url": {"https://ci.example/h"}, "secretRef": {"env://WH"}}
	for path, v := range map[string]url.Values{"/webhooks": add, "/webhooks/ci/remove": {"confirm": {"yes"}}} {
		before := p.impr.count()
		code, body, _ := p.post(path, v, true)
		if code != http.StatusForbidden || p.impr.count() != before || !strings.Contains(body, "server.allowAdmin") {
			t.Errorf("POST %s without allowAdmin: %d, ran %d", path, code, p.impr.count()-before)
		}
	}
	for _, path := range []string{"/webhooks/ci/test", "/webhooks/retry"} {
		if code, _, _ := p.post(path, nil, true); code != http.StatusSeeOther {
			t.Errorf("POST %s: %d", path, code)
		}
	}
	_, page, _ := p.get("/webhooks")
	if !strings.Contains(page, "server.allowAdmin") || !strings.Contains(page, "impr config set server.allowAdmin true") ||
		!regexp.MustCompile(`<button type="submit" class="btn btn-sm btn-outline-danger"[^>]* disabled`).MatchString(page) {
		t.Error("/webhooks does not show the remove button disabled with the reason and the fix")
	}
	if _, form, _ := p.get("/webhooks/new"); !strings.Contains(form, "<fieldset disabled") || !strings.Contains(form, "server.allowAdmin") {
		t.Error("/webhooks/new does not show its form disabled with the reason")
	}
	for name, edit := range map[string]func(*Options){
		"allowAdmin":         func(o *Options) { o.AllowAdmin = true },
		"webhookAdmin owner": func(o *Options) { o.Web.WebhookAdmin = config.WebhookAdminOwner },
	} {
		q := newPagesWith(t, false, edit)
		if code, _, _ := q.post("/webhooks", add, true); code != http.StatusSeeOther || !q.impr.ranLine("webhooks add ci2") {
			t.Errorf("%s: POST /webhooks: %d", name, code)
		}
		if _, page, _ := q.get("/webhooks"); strings.Contains(page, "<fieldset disabled") || strings.Contains(page, "impr config set server.allowAdmin true") {
			t.Errorf("%s: the webhooks page still says writes are off", name)
		}
	}
}
