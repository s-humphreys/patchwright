// Package support answers whether the line an image is built on is still being
// maintained, and which line a team could move to instead.
//
// It exists because of a specific way a vulnerability queue lies. An image pinned to a
// runtime's dead major sits on the newest build of that tag forever: nothing newer will
// ever be published, so a resolver that compares versions finds nothing and a resolver
// that compares digests sees a digest that never moves. Both report "no upgrade
// available", which the queue renders as an empty Fix column, which reads as
// nothing-to-do — on an image that will accumulate criticals for the rest of its life.
//
// The fix is not to recommend the newest thing available. That is the other failure: the
// newest major of a runtime is routinely one nobody should adopt yet, and recommending it
// produces advice a team correctly ignores. Node is the worked example. When Node 20 went
// end of life, the registry held 22, 24 and 26; 26 was Current with its LTS date still in
// the future, so the takeable answer was 24 — the newest line that is BOTH still
// maintained and already LTS.
//
// So this package answers three things, and the distinction between the second and third
// is the whole point:
//
//   - Is the current line still maintained?
//   - What is the newest line that exists?
//   - What is the newest line a team could actually adopt today?
package support

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/pkg/httpretry"
)

// Cycle is one maintained line of a product, as endoflife.date describes it.
type Cycle struct {
	// Name is the cycle identifier, which is the version prefix it covers: "20" for
	// Node, "3.12" for Python. Its granularity differs per product, which is why
	// matching a version to a cycle is a prefix match rather than a parse.
	Name string
	// EOL is when maintenance ends, when a date was given. Zero means no date, which
	// is not on its own a statement that the line is alive: see NoEnd for the case
	// where the product says so explicitly.
	EOL time.Time
	// EOLKnown reports whether an end date was stated at all.
	EOLKnown bool
	// NoEnd is the feed explicitly saying `eol: false`, which is how a product says
	// "this line is maintained and no end has been announced". Go uses it for its two
	// newest releases. That is a positive statement by the source, so it counts as
	// supported; it is not the same as the field being ABSENT, which is silence and
	// stays unknown.
	NoEnd bool
	// LTS is when this cycle became (or becomes) long-term supported. A date in the
	// future means it is not LTS yet, which is exactly the Node 26 case: present in
	// the registry, promoted later, not adoptable today.
	LTS time.Time
	// HasLTS reports whether this cycle is ever designated LTS.
	HasLTS bool
}

// Supported reports whether the cycle is maintained as at the given day, and whether
// the feed said anything at all.
//
// Three outcomes, and keeping them apart is the point: a date in the future is
// supported, a date in the past is not, and SILENCE is neither. A product that has not
// said when a line dies has not said the line is alive, so an absent end date reports
// known=false and callers must render it as "not checked" rather than as good news. An
// explicit `eol: false` is not silence: it is the product saying no end is announced.
func (c Cycle) Supported(on time.Time) (supported, known bool) {
	if c.EOLKnown {
		return c.EOL.After(on), true
	}
	if c.NoEnd {
		return true, true
	}
	return false, false
}

// AdoptableOn reports whether a team could reasonably move onto this cycle today:
// maintained, and if the product designates LTS lines at all, already promoted to one.
func (c Cycle) AdoptableOn(on time.Time, productHasLTS bool) bool {
	if s, known := c.Supported(on); !known || !s {
		return false
	}
	if productHasLTS {
		return c.HasLTS && !c.LTS.After(on)
	}
	return true
}

// Product is the set of cycles for one piece of software.
type Product struct {
	Name   string
	Cycles []Cycle
}

// HasLTS reports whether this product designates LTS lines at all. Products that do not
// (Alpine, for instance) must not have an LTS test applied to them, or nothing would
// ever be adoptable.
func (p Product) HasLTS() bool {
	for _, c := range p.Cycles {
		if c.HasLTS {
			return true
		}
	}
	return false
}

// Cycle finds the cycle covering a version, by longest matching prefix.
//
// Prefix rather than parse because cycle granularity is the product's choice, not a
// convention: Node's cycles are majors ("20" covers 20.19.5), Python's are minors
// ("3.12" covers 3.12.7, and "3" would be wrong). Longest match picks the most specific
// line the product actually maintains.
func (p Product) Cycle(version string) (Cycle, bool) {
	want := components(version)
	var best Cycle
	bestLen := 0
	for _, c := range p.Cycles {
		have := components(c.Name)
		if len(have) == 0 || len(have) > len(want) || len(have) <= bestLen {
			continue
		}
		match := true
		for i, part := range have {
			if want[i] != part {
				match = false
				break
			}
		}
		if match {
			best, bestLen = c, len(have)
		}
	}
	return best, bestLen > 0
}

// Adoptable returns the newest cycle a team could move onto today, and the newest that
// exists at all. They differ when the newest line is not yet adoptable, and reporting
// both is what lets a caller say "24 now, 26 when it is promoted" instead of choosing
// silently.
func (p Product) Adoptable(on time.Time) (adoptable Cycle, newest Cycle, ok bool) {
	cycles := append([]Cycle(nil), p.Cycles...)
	sort.Slice(cycles, func(i, j int) bool { return lessCycle(cycles[i].Name, cycles[j].Name) })
	hasLTS := p.HasLTS()
	for _, c := range cycles {
		newest = c
		if c.AdoptableOn(on, hasLTS) {
			adoptable, ok = c, true
		}
	}
	return adoptable, newest, ok
}

// Nearest returns the oldest adoptable cycle strictly newer than the one given.
//
// Reported alongside Adoptable because they answer different questions and a team should
// get to choose. Moving off a dead Python 3.9 to 3.14 buys the longest runway; moving to
// 3.11 is the smallest change that stops the bleeding. Naming only one of them turns a
// judgement about migration cost into a decision this tool has no business making.
func (p Product) Nearest(on time.Time, current string) (Cycle, bool) {
	cycles := append([]Cycle(nil), p.Cycles...)
	sort.Slice(cycles, func(i, j int) bool { return lessCycle(cycles[i].Name, cycles[j].Name) })
	hasLTS := p.HasLTS()
	for _, c := range cycles {
		if !lessCycle(current, c.Name) {
			continue
		}
		if c.AdoptableOn(on, hasLTS) {
			return c, true
		}
	}
	return Cycle{}, false
}

// components splits a version into its dotted numeric-ish parts, ignoring any suffix:
// "20-alpine" is the 20 line, "3.12-slim" the 3.12 line.
func components(v string) []string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+_"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	return strings.Split(v, ".")
}

// lessCycle orders cycle names numerically per component, so 9 sorts below 20 rather
// than above it as a string comparison would have it.
func lessCycle(a, b string) bool {
	as, bs := components(a), components(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := strconv.Atoi(as[i])
		bi, berr := strconv.Atoi(bs[i])
		if aerr != nil || berr != nil {
			if as[i] != bs[i] {
				return as[i] < bs[i]
			}
			continue
		}
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}

// Source resolves support windows for a product.
type Source interface {
	// Name identifies the source in logs and in the report's coverage line.
	Name() string
	// Product returns the cycles for a product name, or an error. An error must be
	// reported as a gap, never absorbed: "we could not check" and "still supported"
	// are opposite answers.
	Product(ctx context.Context, product string) (Product, error)
}

// endOfLife reads endoflife.date.
type endOfLife struct {
	baseURL string
	client  *http.Client
	cache   map[string]Product
	failed  map[string]error
}

// NewEndOfLife returns a Source backed by endoflife.date.
func NewEndOfLife(baseURL string, client *http.Client) Source {
	if baseURL == "" {
		baseURL = "https://endoflife.date/api"
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &endOfLife{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client:  client,
		cache:   map[string]Product{},
		failed:  map[string]error{},
	}
}

func (e *endOfLife) Name() string { return "endoflife.date" }

// cycleJSON mirrors one entry of endoflife.date's product feed.
//
// eol and lts are json.RawMessage because the feed uses a union: a date string when
// there is one, the boolean false when there is not. Decoding either into a string or a
// bool alone fails on half the products.
type cycleJSON struct {
	Cycle string          `json:"cycle"`
	EOL   json.RawMessage `json:"eol"`
	LTS   json.RawMessage `json:"lts"`
}

func (e *endOfLife) Product(ctx context.Context, product string) (Product, error) {
	if p, ok := e.cache[product]; ok {
		return p, nil
	}
	if err, ok := e.failed[product]; ok {
		return Product{}, err
	}
	p, err := e.fetch(ctx, product)
	if err != nil {
		// Remembered so a run does not retry a 404 once per image: a product this
		// source has never heard of is a stable answer.
		e.failed[product] = err
		return Product{}, err
	}
	e.cache[product] = p
	return p, nil
}

func (e *endOfLife) fetch(ctx context.Context, product string) (Product, error) {
	url := fmt.Sprintf("%s/%s.json", e.baseURL, product)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Product{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpretry.Do(ctx, e.client, req, httpretry.Attempts)
	if err != nil {
		return Product{}, fmt.Errorf("support windows for %s: %w", product, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Product{}, fmt.Errorf("support windows for %s: unexpected status %s", product, resp.Status)
	}
	var raw []cycleJSON
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Product{}, fmt.Errorf("support windows for %s: decode: %w", product, err)
	}
	out := Product{Name: product}
	for _, c := range raw {
		cy := Cycle{Name: c.Cycle}
		if d, ok := asDate(c.EOL); ok {
			cy.EOL, cy.EOLKnown = d, true
		} else if isFalse(c.EOL) {
			cy.NoEnd = true
		}
		if d, ok := asDate(c.LTS); ok {
			cy.LTS, cy.HasLTS = d, true
		} else if asTrue(c.LTS) {
			// LTS true with no date: already long-term supported.
			cy.HasLTS = true
		}
		out.Cycles = append(out.Cycles, cy)
	}
	if len(out.Cycles) == 0 {
		return Product{}, fmt.Errorf("support windows for %s: no cycles in feed", product)
	}
	return out, nil
}

// asDate reads the date form of the union, if that is what this value is.
func asDate(raw json.RawMessage) (time.Time, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func asTrue(raw json.RawMessage) bool {
	var b bool
	return json.Unmarshal(raw, &b) == nil && b
}

// isFalse reports the explicit `false` form, as distinct from the field being absent.
func isFalse(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	return json.Unmarshal(raw, &b) == nil && !b
}
