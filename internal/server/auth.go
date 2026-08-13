package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
)

// Authentication for the API and the status page.
//
// A single shared token, supplied two ways so one mechanism serves both kinds of
// client:
//
//   - `Authorization: Bearer <token>` for programmatic callers (curl, Backstage,
//     the MCP server).
//   - HTTP Basic with the token as the password, for browsers. A browser cannot
//     attach a bearer token when it navigates to a page, so gating the page on
//     bearer alone would leave only two options: a bespoke login flow, or leaving
//     the page open. Basic is unglamorous but native, and once the browser has
//     the credentials it sends them on the page's own fetches too.
//
// This is deliberately the floor, not the ceiling: one shared secret with no
// identity and no per-team scoping. Anything beyond a trusted network wants OIDC
// in front (an ingress authenticator or oauth2-proxy), which this does not
// replace. It exists so the service is not wide open the moment it is exposed,
// and so write endpoints have something to sit behind.

// openPaths are reachable without a token. Probes must not need a credential, and
// the favicon carries no data.
//
// /metrics is here too, because a scrape config that needs a bearer token is
// friction in the place least likely to be tolerated: an operator adding a
// dashboard should not have to negotiate credentials with the team that runs
// Prometheus. It is not a costless default — the metrics count unpatched criticals
// and per-team coverage gaps, so anything that can reach the port can read the
// estate's shape. Network policy is the control there, and WithMetricsAuth exists
// for deployments that would rather pay the friction.
var openPaths = map[string]bool{
	"/healthz":     true,
	"/readyz":      true,
	"/favicon.png": true,
	"/metrics":     true,
}

// WithMetricsAuth brings /metrics under the shared token, for a deployment that
// treats coverage counts as sensitive. Off by default: see openPaths.
//
// Has no effect when no token is configured, since there would be nothing to
// require — silently "protecting" an endpoint on a server with authentication
// disabled would be worse than leaving it open honestly.
func (s *Server) WithMetricsAuth(required bool) *Server {
	s.metricsAuth = required
	return s
}

// WithAuth requires the given token on every request except openPaths. An empty
// token disables authentication entirely.
func (s *Server) WithAuth(token string) *Server {
	if token != "" {
		// Compare digests rather than raw bytes so the comparison is
		// length-independent as well as constant-time.
		sum := sha256.Sum256([]byte(token))
		s.tokenDigest = sum[:]
	}
	return s
}

// authenticated reports whether authentication is configured.
func (s *Server) authenticated() bool { return len(s.tokenDigest) > 0 }

// openPath reports whether a path needs no token. Metrics are open unless the
// deployment has asked for them to be gated, which is the one openPaths entry that
// is a policy choice rather than a necessity.
func (s *Server) openPath(path string) bool {
	if path == "/metrics" && s.metricsAuth {
		return false
	}
	return openPaths[path]
}

// authorize wraps h, rejecting requests without a valid token.
func (s *Server) authorize(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated() || s.openPath(r.URL.Path) {
			h.ServeHTTP(w, r)
			return
		}
		if s.tokenValid(presentedToken(r)) {
			h.ServeHTTP(w, r)
			return
		}
		// Advertise Basic so a browser prompts rather than showing a bare 401.
		w.Header().Set("WWW-Authenticate", `Basic realm="patchwright", charset="UTF-8"`)
		slog.DebugContext(r.Context(), "rejected unauthenticated request", "path", r.URL.Path)
		writeError(w, http.StatusUnauthorized, "unauthorized")
	})
}

// presentedToken extracts a token from either supported scheme. Returns "" when
// the header is absent or malformed, which fails the comparison below.
func presentedToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	if rest, ok := cutPrefixFold(header, "Bearer "); ok {
		return strings.TrimSpace(rest)
	}
	if strings.HasPrefix(strings.ToLower(header), "basic ") {
		// The username is ignored: the token is the secret, and requiring a
		// particular username would be a second thing to configure for no gain.
		if _, password, ok := r.BasicAuth(); ok {
			return password
		}
	}
	return ""
}

// tokenValid compares in constant time, so a wrong token cannot be discovered by
// timing how long the rejection takes.
func (s *Server) tokenValid(presented string) bool {
	if presented == "" {
		return false
	}
	sum := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(sum[:], s.tokenDigest) == 1
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}
