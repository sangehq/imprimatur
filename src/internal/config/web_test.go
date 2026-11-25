package config

import (
	"strings"
	"testing"
)

// server.web.tokenAccess and server.web.webhookAdmin take their documented
// values only; unset is the default (owner, 2026-11-25).
func TestServerWebSettingsAreValidated(t *testing.T) {
	ok := func(w ServerWeb) []string {
		return Config{Schema: Schema, Server: Server{Web: w}}.Validate()
	}
	for _, w := range []ServerWeb{{}, {TokenAccess: TokenAccessSecrets}, {TokenAccess: TokenAccessScopes},
		{WebhookAdmin: WebhookAdminAllowAdmin}, {WebhookAdmin: WebhookAdminOwner}} {
		if ps := ok(w); len(ps) != 0 {
			t.Errorf("%+v: %v", w, ps)
		}
	}
	for _, tc := range []struct {
		w    ServerWeb
		want string
	}{
		{ServerWeb{TokenAccess: TokenAccessSecrets + "+" + TokenAccessScopes}, "server.web.tokenAccess"},
		{ServerWeb{TokenAccess: strings.ToUpper(TokenAccessScopes)}, "server.web.tokenAccess"}, // values are case-sensitive
		{ServerWeb{WebhookAdmin: "anyone"}, "server.web.webhookAdmin"},
	} {
		ps := ok(tc.w)
		if len(ps) != 1 || !strings.Contains(ps[0], tc.want) {
			t.Errorf("%+v: %v, want one problem naming %s", tc.w, ps, tc.want)
		}
	}
	var s Server
	if s.Web.TokenScopes() || !s.Web.WebhooksNeedAllowAdmin() {
		t.Error("the defaults are not secrets-only and allowAdmin")
	}
	if !(ServerWeb{TokenAccess: TokenAccessScopes}).TokenScopes() || (ServerWeb{WebhookAdmin: WebhookAdminOwner}).WebhooksNeedAllowAdmin() {
		t.Error("the other values do not switch")
	}
}
