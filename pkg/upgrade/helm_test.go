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

func TestCheckChartNotFound(t *testing.T) {
	srv := serveIndex(t)
	defer srv.Close()
	if _, err := NewHelmChecker().Check(context.Background(), ChartRef{RepoURL: srv.URL, Name: "missing", Version: "1.0.0"}); err == nil {
		t.Error("expected error for a chart not in the index")
	}
}
