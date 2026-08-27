package support_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/s-humphreys/patchwright/pkg/support"
)

func date(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// The real Node situation on the day this was written, which is the case the package
// exists for: 20 is dead, 22 and 24 are LTS, 26 exists but is promoted to LTS later.
func nodeProduct() support.Product {
	return support.Product{Name: "nodejs", Cycles: []support.Cycle{
		{Name: "20", EOL: date("2026-04-30"), EOLKnown: true, LTS: date("2023-10-24"), HasLTS: true},
		{Name: "22", EOL: date("2027-04-30"), EOLKnown: true, LTS: date("2024-10-29"), HasLTS: true},
		{Name: "24", EOL: date("2028-04-30"), EOLKnown: true, LTS: date("2025-10-28"), HasLTS: true},
		{Name: "26", EOL: date("2029-04-30"), EOLKnown: true, LTS: date("2026-10-28"), HasLTS: true},
		{Name: "27", EOL: date("2030-04-30"), EOLKnown: true},
	}}
}

func TestTheNewestLineIsNotTheAdoptableOne(t *testing.T) {
	// The whole point. On this day Node 26 is in the registry and maintained, but its
	// LTS date has not arrived, so recommending it would put a team on Current.
	// Recommending the newest available is the mistake this replaces, not the fix.
	on := date("2026-08-27")
	adoptable, newest, ok := nodeProduct().Adoptable(on)
	if !ok {
		t.Fatal("no adoptable cycle found")
	}
	if adoptable.Name != "24" {
		t.Errorf("adoptable = %q, want 24 (newest already-LTS maintained line)", adoptable.Name)
	}
	if newest.Name != "27" {
		t.Errorf("newest = %q, want 27 (what exists, reported so a caller can say 'later')", newest.Name)
	}
}

func TestOnceItsLTSDateArrivesItBecomesAdoptable(t *testing.T) {
	// Same data, a later day: the recommendation moves on its own, without anyone
	// editing a table. That is the argument for reading support windows rather than
	// hardcoding them.
	adoptable, _, ok := nodeProduct().Adoptable(date("2026-11-01"))
	if !ok || adoptable.Name != "26" {
		t.Errorf("adoptable = %q ok=%v, want 26 after its LTS date", adoptable.Name, ok)
	}
}

func TestAnEndOfLifeLineIsReportedAsSuchAndAnUnknownOneIsNot(t *testing.T) {
	on := date("2026-08-27")
	p := nodeProduct()

	dead, ok := p.Cycle("20.19.5")
	if !ok {
		t.Fatal("20.19.5 did not match the 20 cycle")
	}
	if s, known := dead.Supported(on); s || !known {
		t.Errorf("node 20 on %s: supported=%v known=%v, want false/true", on, s, known)
	}

	// A cycle with no stated end date must report unknown, NOT supported. Absence of
	// an end date is absence of information, and this queue must never turn that into
	// good news.
	unknown := support.Cycle{Name: "99"}
	if s, known := unknown.Supported(on); s || known {
		t.Errorf("cycle with no EOL date: supported=%v known=%v, want false/false", s, known)
	}
	if unknown.AdoptableOn(on, true) {
		t.Error("a cycle with no support data must not be recommended as a target")
	}
}

func TestCycleGranularityIsTheProductsChoice(t *testing.T) {
	// Node files cycles by major, Python by minor. A parse would have to know which;
	// a longest-prefix match does not.
	python := support.Product{Name: "python", Cycles: []support.Cycle{
		{Name: "3", EOLKnown: true, EOL: date("2030-01-01")},
		{Name: "3.11", EOLKnown: true, EOL: date("2027-10-31")},
		{Name: "3.12", EOLKnown: true, EOL: date("2028-10-31")},
	}}
	c, ok := python.Cycle("3.12.7")
	if !ok || c.Name != "3.12" {
		t.Errorf("python 3.12.7 matched %q (ok=%v), want the 3.12 line, not 3", c.Name, ok)
	}
	n, ok := nodeProduct().Cycle("20-alpine")
	if !ok || n.Name != "20" {
		t.Errorf("node 20-alpine matched %q (ok=%v), want 20: the suffix is a variant, not a version", n.Name, ok)
	}
}

func TestCyclesSortNumericallyNotAsStrings(t *testing.T) {
	// "9" must not outrank "20". A string comparison gets this wrong and would
	// recommend an older line as the newest.
	p := support.Product{Name: "x", Cycles: []support.Cycle{
		{Name: "9", EOLKnown: true, EOL: date("2029-01-01")},
		{Name: "20", EOLKnown: true, EOL: date("2029-01-01")},
	}}
	adoptable, _, ok := p.Adoptable(date("2026-08-27"))
	if !ok || adoptable.Name != "20" {
		t.Errorf("adoptable = %q, want 20", adoptable.Name)
	}
}

func TestProductsWithoutLTSAreNotHeldToAnLTSTest(t *testing.T) {
	// Alpine has no LTS designation. Applying one would make nothing adoptable and
	// silently produce no recommendation at all.
	alpine := support.Product{Name: "alpine", Cycles: []support.Cycle{
		{Name: "3.19", EOLKnown: true, EOL: date("2025-11-01")},
		{Name: "3.21", EOLKnown: true, EOL: date("2027-11-01")},
	}}
	adoptable, _, ok := alpine.Adoptable(date("2026-08-27"))
	if !ok || adoptable.Name != "3.21" {
		t.Errorf("adoptable = %q ok=%v, want 3.21", adoptable.Name, ok)
	}
}

func TestTheFeedsBooleanAndDateFormsBothDecode(t *testing.T) {
	// endoflife.date uses a union: a date when there is one, `false` when there is
	// not. Half the products use each, so a decoder that assumes one shape fails on
	// the other half.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodejs.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[
		  {"cycle":"24","eol":"2028-04-30","lts":"2025-10-28"},
		  {"cycle":"27","eol":false,"lts":false},
		  {"cycle":"22","eol":"2027-04-30","lts":true}
		]`))
	}))
	defer srv.Close()

	s := support.NewEndOfLife(srv.URL, srv.Client())
	p, err := s.Product(context.Background(), "nodejs")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Cycles) != 3 {
		t.Fatalf("cycles = %d, want 3", len(p.Cycles))
	}
	byName := map[string]support.Cycle{}
	for _, c := range p.Cycles {
		byName[c.Name] = c
	}
	if c := byName["27"]; c.EOLKnown {
		t.Error(`eol:false must decode as "no end date stated", not as a date`)
	}
	if c := byName["22"]; !c.HasLTS {
		t.Error("lts:true must mark the cycle long-term supported")
	}
	if c := byName["24"]; !c.HasLTS || !c.LTS.Equal(date("2025-10-28")) {
		t.Errorf("lts date not read: %+v", c)
	}
}

func TestNoAnnouncedEndIsSupportedButAMissingFieldIsUnknown(t *testing.T) {
	// Go's convention: its two newest releases carry `eol: false`, meaning maintained
	// with no announced end. Reading that as "unknown" made Go unrecommendable, so an
	// image on a dead Go would have been flagged with nowhere to go.
	//
	// The distinction that matters: `eol: false` is the source SAYING something, while
	// an absent field is silence, and only the former counts as supported.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
		  {"cycle":"1.27","eol":false,"lts":false},
		  {"cycle":"1.26","eol":false,"lts":false},
		  {"cycle":"1.25","eol":"2026-08-19","lts":false},
		  {"cycle":"0.9"}
		]`))
	}))
	defer srv.Close()

	p, err := support.NewEndOfLife(srv.URL, srv.Client()).Product(context.Background(), "go")
	if err != nil {
		t.Fatal(err)
	}
	on := date("2026-08-27")
	adoptable, newest, ok := p.Adoptable(on)
	if !ok || adoptable.Name != "1.27" {
		t.Errorf("adoptable = %q ok=%v, want 1.27: no announced end means maintained", adoptable.Name, ok)
	}
	if newest.Name != "1.27" {
		t.Errorf("newest = %q, want 1.27", newest.Name)
	}

	byName := map[string]support.Cycle{}
	for _, c := range p.Cycles {
		byName[c.Name] = c
	}
	if s, known := byName["1.25"].Supported(on); s || !known {
		t.Errorf("1.25 (eol in the past): supported=%v known=%v, want false/true", s, known)
	}
	if s, known := byName["0.9"].Supported(on); s || known {
		t.Errorf("0.9 (no eol field at all): supported=%v known=%v, want false/false - silence is not an answer", s, known)
	}
}

func TestAnUnknownProductIsAnErrorNotAnEmptyAnswer(t *testing.T) {
	// A 404 must surface. Returning an empty product would make every image on it
	// look like it had been checked and found fine.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	s := support.NewEndOfLife(srv.URL, srv.Client())
	if _, err := s.Product(context.Background(), "nosuchthing"); err == nil {
		t.Fatal("want an error for an unknown product")
	}
}

func TestProductLookupMatchesTheMostSpecificPathAndIgnoresMirrors(t *testing.T) {
	cases := []struct {
		repo, want string
	}{
		{"docker.io/library/node", "nodejs"},
		{"node", "nodejs"},
		{"example.azurecr.io/dockerhub/node", "nodejs"},
		{"mcr.microsoft.com/dotnet/aspnet", "dotnet"},
		{"mcr.microsoft.com/dotnet/nightly/sdk", "dotnet"},
		{"alpine", "alpine"},
		{"example.azurecr.io/some-internal-app", ""},
	}
	for _, c := range cases {
		got, ok := support.ProductFor(c.repo, nil)
		if c.want == "" {
			if ok {
				t.Errorf("%s: identified as %q, want no guess at all", c.repo, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("%s: got %q (ok=%v), want %q", c.repo, got, ok, c.want)
		}
	}
}

func TestAConfiguredOverrideWinsOverTheBuiltInTable(t *testing.T) {
	// The case that makes this usable on a real estate: a first-party base image
	// nobody upstream has heard of, declared as the thing it is built from.
	over := map[string]string{
		"example.azurecr.io/dotnet/aspnet/10": "dotnet",
		"node":                                "nodejs-fork",
	}
	if got, ok := support.ProductFor("example.azurecr.io/dotnet/aspnet/10", over); !ok || got != "dotnet" {
		t.Errorf("override not applied: got %q ok=%v", got, ok)
	}
	if got, _ := support.ProductFor("docker.io/library/node", over); got != "nodejs-fork" {
		t.Errorf("override must outrank the built-in table, got %q", got)
	}
}

func TestNearestIsOfferedAlongsideNewest(t *testing.T) {
	// A team on a dead line should be told both: the smallest move that stops the
	// bleeding, and the one with the longest runway. Choosing for them would hide a
	// migration-cost judgement inside a version string.
	python := support.Product{Name: "python", Cycles: []support.Cycle{
		{Name: "3.9", EOLKnown: true, EOL: date("2025-10-31")},
		{Name: "3.11", EOLKnown: true, EOL: date("2027-10-31")},
		{Name: "3.12", EOLKnown: true, EOL: date("2028-10-31")},
		{Name: "3.14", EOLKnown: true, EOL: date("2030-10-31")},
	}}
	on := date("2026-08-27")
	nearest, ok := python.Nearest(on, "3.9")
	if !ok || nearest.Name != "3.11" {
		t.Errorf("nearest = %q ok=%v, want 3.11 (smallest supported move)", nearest.Name, ok)
	}
	adoptable, _, _ := python.Adoptable(on)
	if adoptable.Name != "3.14" {
		t.Errorf("adoptable = %q, want 3.14 (longest runway)", adoptable.Name)
	}
	// Nothing newer than the newest line, so there is no nearest to offer.
	if _, ok := python.Nearest(on, "3.14"); ok {
		t.Error("want no nearest cycle above the newest one")
	}
}
