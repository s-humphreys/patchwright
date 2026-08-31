package server

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// This file is about the wire rather than the data: the same answers, sent in a way
// a browser on the other side of a VPN can actually work with.
//
// It exists because of a measurement. The findings payload for a real estate is 41MB
// of JSON - 612 findings carrying 208,697 CVEs between them - and it was served
// uncompressed, then re-fetched in full every sixty seconds. Nothing about the page's
// rendering could compensate for that: the data had not arrived yet.
//
// Two things fix most of it, and neither changes an answer.
//
// Compression, because this shape of JSON is enormously repetitive - the same field
// names 208,697 times - and gzips 16x. And revalidation, because an assessment is
// immutable between refreshes, so a client that already has the current one should be
// told "unchanged" in 200 bytes rather than sent it again.

// gzipMinSize is the size below which compressing costs more than it saves. A gzip
// header plus a trailer is around 20 bytes, and for anything this small the CPU and
// the loss of streaming are not worth it.
const gzipMinSize = 1024

// compressible is the content this server produces that is worth compressing: text
// that repeats itself. Images and anything already encoded are left alone.
func compressible(contentType string) bool {
	ct, _, _ := strings.Cut(contentType, ";")
	switch strings.TrimSpace(ct) {
	case "application/json", "text/html", "text/javascript", "text/css", "text/plain",
		"application/openmetrics-text":
		return true
	}
	return false
}

var gzipPool = sync.Pool{
	New: func() any {
		// Level 5 rather than the default 6: on the 41MB payload that was 107ms of CPU
		// against 180ms for a 4% larger body, and this runs per request on a service
		// whose other job is a 25-minute assessment holding several GB.
		w, _ := gzip.NewWriterLevel(io.Discard, 5)
		return w
	},
}

// compress negotiates gzip for responses worth compressing.
//
// Deliberately decided at WriteHeader rather than at request time, because the
// handler is what knows the content type - and because a handler that has already set
// Content-Encoding itself (the metrics handler negotiates its own) must be left
// alone rather than compressed twice.
func compress(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !acceptsGzip(r) {
			h.ServeHTTP(w, r)
			return
		}
		// Announced whether or not this particular response ends up compressed: a
		// shared cache that stored one client's uncompressed copy under the same key
		// would hand it to a client expecting gzip.
		w.Header().Add("Vary", "Accept-Encoding")
		gw := &gzipWriter{ResponseWriter: w}
		defer gw.close()
		h.ServeHTTP(gw, r)
	})
}

func acceptsGzip(r *http.Request) bool {
	for _, enc := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(enc), ";")
		if strings.EqualFold(name, "gzip") {
			return true
		}
	}
	return false
}

// gzipWriter compresses a response, deciding on the first write whether to.
//
// The buffering is not incidental. Content type is known at WriteHeader, but SIZE is
// not, and a 200-byte error should not be gzipped. So the first gzipMinSize bytes are
// held, and the decision is made once there is enough evidence: a short response
// passes through untouched, a long one starts a gzip stream and keeps streaming.
//
// The status is held with the body, and holding it is the subtle part. An earlier
// version of this let the first Write default the status to 200 without checking
// whether the handler had already chosen one, which turned every 403 from the sign-in
// flow into a 403-shaped body served as 200. Hence status and statusSet: "no status
// yet" and "200" have to be different states.
type gzipWriter struct {
	http.ResponseWriter

	status    int
	statusSet bool
	// headerSent records that the status line has gone out, after which neither it nor
	// the headers can change.
	headerSent bool
	// gzip is non-nil once this response is being compressed, and pending holds the
	// start of a body whose fate is not yet decided.
	gzip    *gzip.Writer
	pending []byte
	// passthrough is set for a response that must not be touched: no body, a content
	// type not worth compressing, one the handler has already encoded, or one short
	// enough that compressing it would cost more than it saves.
	passthrough bool
	decided     bool
}

func (g *gzipWriter) WriteHeader(status int) {
	if g.headerSent {
		return
	}
	if !g.statusSet {
		g.status, g.statusSet = status, true
	}
	h := g.Header()
	// 204 and 304 carry no body, and a handler that encoded its own body owns it.
	if status == http.StatusNoContent || status == http.StatusNotModified ||
		h.Get("Content-Encoding") != "" || !compressible(h.Get("Content-Type")) {
		g.passthrough, g.decided = true, true
	}
	// A body whose length is already known and small is not worth compressing, and
	// keeping its Content-Length is better than replacing it with a stream.
	if n, err := strconv.Atoi(h.Get("Content-Length")); err == nil && n < gzipMinSize {
		g.passthrough, g.decided = true, true
	}
	if g.decided {
		g.sendHeader()
	}
	// Otherwise the status line is held until the first write decides, so that the
	// gzip headers can still be set.
}

func (g *gzipWriter) sendHeader() {
	if g.headerSent {
		return
	}
	g.headerSent = true
	if !g.statusSet {
		g.status, g.statusSet = http.StatusOK, true
	}
	g.ResponseWriter.WriteHeader(g.status)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.decided && !g.headerSent {
		// A handler writing without a status has chosen 200, but only if it has not
		// chosen one already.
		g.WriteHeader(http.StatusOK)
	}
	switch {
	case g.passthrough:
		return g.ResponseWriter.Write(b)
	case g.gzip != nil:
		return g.gzip.Write(b)
	}
	g.pending = append(g.pending, b...)
	if len(g.pending) < gzipMinSize {
		return len(b), nil
	}
	g.startGzip()
	return len(b), nil
}

// startGzip commits to compressing and flushes what was held back.
func (g *gzipWriter) startGzip() {
	h := g.Header()
	h.Set("Content-Encoding", "gzip")
	// The length of the uncompressed body, which is no longer what is being sent. Left
	// in place it would truncate the response at the client.
	h.Del("Content-Length")
	g.decided = true
	g.sendHeader()
	g.gzip = gzipPool.Get().(*gzip.Writer)
	g.gzip.Reset(g.ResponseWriter)
	_, _ = g.gzip.Write(g.pending)
	g.pending = nil
}

// close finishes the response: a compressed stream is terminated, and a body still
// small enough to be held is sent as it is.
func (g *gzipWriter) close() {
	if g.gzip != nil {
		_ = g.gzip.Close()
		gzipPool.Put(g.gzip)
		g.gzip = nil
		return
	}
	g.decided = true
	g.sendHeader()
	if len(g.pending) > 0 {
		_, _ = g.ResponseWriter.Write(g.pending)
		g.pending = nil
	}
}

// Flush lets a streaming handler through. Without it, wrapping breaks anything that
// relies on flushing - which on this server is the MCP endpoint's event stream. A
// handler that flushes has decided its body is not to be held.
func (g *gzipWriter) Flush() {
	if !g.decided && !g.headerSent {
		g.WriteHeader(http.StatusOK)
	}
	if !g.decided && len(g.pending) > 0 {
		g.startGzip()
	}
	if g.gzip != nil {
		_ = g.gzip.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets net/http reach the underlying writer for hijacking and for
// ResponseController, so wrapping does not quietly disable them.
func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// revalidate answers "have you still got the current assessment?" without sending it
// again.
//
// The tag is derived from the assessment rather than from the body, which is the
// whole point: hashing 41MB to decide whether to send 41MB saves only the bandwidth,
// and the encoding is the expensive half. An assessment is immutable once cached, so
// its timestamp plus the request's own URI identifies the answer exactly - a
// different query string is a different answer, and a different build can serialise
// the same data differently.
//
// Only for GETs on the read API. Anything unauthenticated (the probes, metrics)
// changes on its own schedule, and a POST is not cacheable.
func (s *Server) revalidate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tag := s.etag(r)
		if tag == "" {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("ETag", tag)
		// no-cache, not no-store: the browser may keep the copy, it just has to ask
		// before using it. That question is what makes this cheap - a poll for
		// unchanged data becomes a 304 with no body rather than a re-download.
		w.Header().Set("Cache-Control", "no-cache")
		if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, tag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// etag returns the validator for a request, or "" for anything that must not be
// revalidated this way.
func (s *Server) etag(r *http.Request) string {
	if r.Method != http.MethodGet {
		return ""
	}
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/v1/"), path == "/", path == "/tickets",
		path == "/analytics", strings.HasPrefix(path, "/static/app/"):
	default:
		return ""
	}
	// An in-flight assessment is deliberately not cacheable: the page shows progress
	// from the meta, and a 304 during a run would freeze that.
	s.mu.RLock()
	running, generated := s.running, ""
	if s.latest != nil {
		generated = s.latest.generatedAt.UTC().Format("20060102150405.000000000")
	}
	s.mu.RUnlock()
	if running {
		return ""
	}
	// An asset is identified by its own bytes, not by the assessment: it must not be
	// re-sent every time a run completes, and hashing the content means a rollout that
	// did not change a module leaves that module cached.
	if strings.HasPrefix(path, "/static/app/") {
		return assetETag(strings.TrimPrefix(path, "/"))
	}
	// Everything else is a view of the cached assessment, which is immutable while it
	// is the current one - so its timestamp, plus the query that selected from it, is
	// an exact identity. It also changes on restart, which is what stops a client
	// reusing an entity a new build would serialise differently.
	if generated == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(generated + "|" + r.URL.RequestURI()))
	return `"` + hex.EncodeToString(sum[:12]) + `"`
}

// assetETags caches one hash per embedded file. Computed on first request rather than
// at startup so a binary that never serves the page pays nothing, and cached because
// the bytes cannot change while the process lives.
var (
	assetETagMu sync.Mutex
	assetETags  = map[string]string{}
)

func assetETag(name string) string {
	assetETagMu.Lock()
	defer assetETagMu.Unlock()
	if tag, ok := assetETags[name]; ok {
		return tag
	}
	body, err := staticFS.ReadFile(name)
	if err != nil {
		// Not an asset we serve. The handler will answer 404; no validator for it.
		assetETags[name] = ""
		return ""
	}
	sum := sha256.Sum256(body)
	tag := `"` + hex.EncodeToString(sum[:12]) + `"`
	assetETags[name] = tag
	return tag
}

// etagMatches implements the If-None-Match comparison: a list of tags, or "*", with
// weak prefixes compared as equal since this server never sends both forms of one
// entity.
func etagMatches(header, tag string) bool {
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for _, candidate := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(candidate), "W/"), tag) {
			return true
		}
	}
	return false
}
