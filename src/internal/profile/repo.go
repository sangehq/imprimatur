package profile

import (
	"regexp"
	"strings"
)

var (
	urlForm = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://(?:[^@/]+@)?([^/:]+)(?::\d+)?/(.+)$`)
	scpForm = regexp.MustCompile(`^(?:[^@/]+@)?([^/:]+):(.+)$`)
)

// RepoIdentity turns a push target into host/owner/repo, lower case:
// git@host:owner/repo.git, ssh://git@host/owner/repo and
// https://host/owner/repo.git all give host/owner/repo. "" when it is not a URL.
func RepoIdentity(url string) string {
	u := strings.TrimSpace(url)
	var host, path string
	if m := urlForm.FindStringSubmatch(u); m != nil {
		host, path = m[1], m[2]
	} else if m := scpForm.FindStringSubmatch(u); m != nil {
		host, path = m[1], m[2]
	} else {
		return ""
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if path == "" || strings.Contains(path, "..") {
		return ""
	}
	return strings.ToLower(host + "/" + path)
}

// MatchRepo reports whether a host/owner/repo identity matches a pattern:
// * and ? within a segment, ** across segments, case-insensitive. A pattern
// with no slash is a host and matches everything on it.
func MatchRepo(pattern, identity string) bool {
	p := strings.TrimSuffix(strings.Trim(strings.ToLower(strings.TrimSpace(pattern)), "/"), ".git")
	if p == "" || p == "*" || p == "**" || identity == "" {
		return false
	}
	if !strings.Contains(p, "/") {
		p += "/**"
	}
	var b strings.Builder
	b.WriteString("^")
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "**" {
			if i == 0 {
				b.WriteString(`(?:[^/]+(?:/[^/]+)*)`)
			} else {
				b.WriteString(`(?:/[^/]+)*`)
			}
			continue
		}
		if i > 0 {
			b.WriteString("/")
		}
		q := regexp.QuoteMeta(s)
		q = strings.ReplaceAll(q, `\*`, `[^/]*`)
		q = strings.ReplaceAll(q, `\?`, `[^/]`)
		b.WriteString(q)
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(strings.ToLower(identity))
}

// AllowsRepo reports whether the push target is in the profile's
// allowedRepos. An empty list allows nothing.
func (p Profile) AllowsRepo(url string) bool {
	id := RepoIdentity(url)
	if id == "" {
		return false
	}
	for _, pat := range p.AllowedRepos {
		if MatchRepo(pat, id) {
			return true
		}
	}
	return false
}
