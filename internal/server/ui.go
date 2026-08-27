package server

import (
	"embed"
	"net/http"
	"strings"
)

// staticFS holds the live-status page. Embedding it keeps `serve` a single
// self-contained binary: the page ships with the API it reads, so the two cannot
// drift apart in a deployment.
//
//go:embed static/index.html static/tickets.html static/favicon.png static/app
var staticFS embed.FS

// handleFavicon serves the logo as the tab icon. Downscaled and cropped from
// docs/images/patchwright.png: the source is 2400px and 5MB, which would be an
// absurd thing to embed for something rendered at 16px.
func (s *Server) handleFavicon(w http.ResponseWriter, _ *http.Request) {
	icon, err := staticFS.ReadFile("static/favicon.png")
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(icon)
}

// handleUI serves the live-status page. It is registered on "GET /", which in
// Go's ServeMux is the catch-all, so anything unrecognised lands here; unknown
// paths are answered with 404 rather than the page, so a mistyped API path does
// not return HTML to a JSON client.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.servePage(w, "static/index.html")
}

// handleTicketsPage serves the ticket plan as a page of its own.
//
// Separate from the dashboard because it has a different subject. The dashboard is about
// the estate; this is about what reconciliation would write to a tracker, and it used to
// sit above the queue where it was unmissable and usually beside the point. Its own page
// also means the dashboard no longer queries the tracker on every load.
func (s *Server) handleTicketsPage(w http.ResponseWriter, _ *http.Request) {
	s.servePage(w, "static/tickets.html")
}

// servePage writes an embedded HTML page.
func (s *Server) servePage(w http.ResponseWriter, name string) {
	page, err := staticFS.ReadFile(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ui unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page is embedded and versioned with the binary, so it must not be
	// cached across a rollout that changes it.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(page)
}

// handleAsset serves the page's JavaScript modules and stylesheet from the same
// embedded tree.
//
// Served as separate files rather than inlined into the page: the browser loads ES
// modules natively, so the page needs no build step, and keeping the modules apart
// is what makes them type-checkable and testable. They sit behind the same auth as
// the page, since together they are the page.
func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	// Only the app directory, and no traversal out of it. Nothing else in the
	// embedded tree is servable.
	if !strings.HasPrefix(name, "static/app/") || strings.Contains(name, "..") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	body, err := staticFS.ReadFile(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch {
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	default:
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	// Same reasoning as the page: embedded and versioned with the binary, so a
	// rollout that changes a module must not be served from cache.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// staticAppFiles returns the contents of every embedded page module. Exposed for
// tests that assert on what the page does, and for the asset route to have one
// definition of what "the app" is.
func staticAppFiles() ([]string, error) {
	entries, err := staticFS.ReadDir("static/app")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		body, err := staticFS.ReadFile("static/app/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, string(body))
	}
	return out, nil
}
