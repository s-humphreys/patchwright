package upgrade

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const indexYAML = `
apiVersion: v1
entries:
  podinfo:
    - version: 6.5.0
    - version: 6.7.1
    - version: 6.8.0-rc.1
    - version: 6.6.2
  other:
    - version: 1.0.0
`

func serveIndex(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(indexYAML))
	})
	return httptest.NewServer(mux)
}

func TestCheckReportsUpgrade(t *testing.T) {
	srv := serveIndex(t)
	defer srv.Close()

	up, err := NewHelmChecker().Check(context.Background(), ChartRef{RepoURL: srv.URL, Name: "podinfo", Version: "6.5.0"})
	if err != nil {
		t.Fatal(err)
	}
	// Latest stable is 6.7.1 (the 6.8.0-rc.1 pre-release is ignored).
	if up.Latest != "6.7.1" {
		t.Errorf("latest: got %q, want 6.7.1", up.Latest)
	}
	if !up.Available {
		t.Error("6.5.0 -> 6.7.1 should be an available upgrade")
	}
	if up.Kind != "chart" || up.Name != "podinfo" || up.Source != srv.URL {
		t.Errorf("unexpected upgrade metadata: %+v", up)
	}
}

func TestCheckNoUpgradeWhenCurrent(t *testing.T) {
	srv := serveIndex(t)
	defer srv.Close()

	up, err := NewHelmChecker().Check(context.Background(), ChartRef{RepoURL: srv.URL, Name: "podinfo", Version: "6.7.1"})
	if err != nil {
		t.Fatal(err)
	}
	if up.Available {
		t.Errorf("already on latest; should not report an upgrade, got %+v", up)
	}
}

func TestCheckIncludesPrereleaseWhenCurrentIsPrerelease(t *testing.T) {
	srv := serveIndex(t)
	defer srv.Close()

	up, err := NewHelmChecker().Check(context.Background(), ChartRef{RepoURL: srv.URL, Name: "podinfo", Version: "6.7.0-rc.1"})
	if err != nil {
		t.Fatal(err)
	}
	if up.Latest != "6.8.0-rc.1" {
		t.Errorf("with a pre-release current, latest should include pre-releases; got %q", up.Latest)
	}
}

func TestCheckOCIRepository(t *testing.T) {
	c := NewHelmChecker()
	// Stub the OCI tag lister instead of hitting a real registry.
	c.ociTags = func(_ context.Context, repo string) ([]string, error) {
		if repo != "ghcr.io/acme/charts/app" {
			t.Errorf("unexpected OCI repo %q", repo)
		}
		return []string{"1.0.0", "1.3.0", "1.1.0", "1.4.0-rc.1"}, nil
	}
	up, err := c.Check(context.Background(), ChartRef{RepoURL: "oci://ghcr.io/acme/charts", Name: "app", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if up.Latest != "1.3.0" || !up.Available || !up.Actionable {
		t.Errorf("OCI chart 1.0.0 should upgrade to 1.3.0 (rc ignored), got %+v", up)
	}
}

func TestCheckChartNotFound(t *testing.T) {
	srv := serveIndex(t)
	defer srv.Close()
	if _, err := NewHelmChecker().Check(context.Background(), ChartRef{RepoURL: srv.URL, Name: "missing", Version: "1.0.0"}); err == nil {
		t.Error("expected error for a chart not in the index")
	}
}

// A chart already on its newest version must not report that version as something to
// move to. It once did, and a consumer reading Latest without Available rendered
// "1.11.0 -> 1.11.0" on an urgent row: a bump that changes nothing, shown instead of
// the real answer, which is that the fix is not a bump.
func TestAChartOnItsNewestVersionOffersNothingToMoveTo(t *testing.T) {
	srv := serveIndex(t)
	defer srv.Close()

	up, err := NewHelmChecker().Check(context.Background(),
		ChartRef{RepoURL: srv.URL, Name: "podinfo", Version: "6.7.1"})
	if err != nil {
		t.Fatal(err)
	}
	if up.Available {
		t.Error("6.7.1 is the newest stable, so no upgrade is available")
	}
	if up.Latest != "" {
		t.Errorf("Latest = %q, want empty: there is no version to move to", up.Latest)
	}
	if up.Current != "6.7.1" {
		t.Errorf("Current = %q, want the version in use", up.Current)
	}
	// Resolved distinguishes this from a lookup that failed: the versions WERE read,
	// and the answer is that this one is the newest.
	if !up.Resolved {
		t.Error("the versions were obtained, so this is a finding rather than a failure")
	}
}
