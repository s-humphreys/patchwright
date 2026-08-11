package server

import (
	"embed"
	"net/http"
)

// staticFS holds the live-status page. Embedding it keeps `serve` a single
// self-contained binary: the page ships with the API it reads, so the two cannot
// drift apart in a deployment.
//
//go:embed static/index.html static/favicon.png
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
	page, err := staticFS.ReadFile("static/index.html")
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
