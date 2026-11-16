// Package redact removes secret-shaped text before it is written anywhere a
// person or another program reads: error messages and documents, log lines,
// events and the audit trail (design §8.5). It is a last line of defence:
// impr keeps secrets as references, so a match here means a value reached
// text it should not have, and it is replaced rather than shown.
package redact

import "regexp"

// Mask replaces a matched secret.
const Mask = "[redacted]"

// patterns are the secret shapes impr knows: its own webhook secrets and API
// tokens, PEM private keys, credentials in a URL or a key=value pair, bearer
// tokens, and the common forge, chat and cloud token formats.
var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`whsec_[A-Za-z0-9+/=]{8,}`),
	regexp.MustCompile(`whsk_[A-Za-z0-9+/=_-]{8,}`),
	regexp.MustCompile(`impr_[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)=[^\s&"']+`),
	regexp.MustCompile(`(?i)\bbearer [A-Za-z0-9._~+/=-]{12,}`),
	regexp.MustCompile(`\b(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
}

// urlCredential is a user and password in a URL; the scheme and host stay.
var urlCredential = regexp.MustCompile(`://[^/\s:@"']+:[^/\s@"']+@`)

// String returns s with every secret shape replaced by Mask. A credential in
// a URL keeps its scheme and host: https://[redacted]@host.
func String(s string) string {
	for _, re := range patterns {
		s = re.ReplaceAllString(s, Mask)
	}
	return urlCredential.ReplaceAllString(s, "://"+Mask+"@")
}

// Strings redacts each element in place and returns the slice.
func Strings(ss []string) []string {
	for i := range ss {
		ss[i] = String(ss[i])
	}
	return ss
}

// Found reports whether s holds a secret shape.
func Found(s string) bool { return String(s) != s }
