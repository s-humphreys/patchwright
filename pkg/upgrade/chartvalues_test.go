package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// packChart builds a packaged chart: files keyed by their path in the archive.
func packChart(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var retoolChart = map[string]string{
	"retool/Chart.yaml":  "name: retool\nversion: 6.11.33\n",
	"retool/values.yaml": "image:\n  repository: tryretool/backend\n  tag: \"\"\ndevicePlugin:\n  image:\n    repository: ghcr.io/smarter-project/smarter-device-manager\n    tag: v1.20.12\n",
	// A subchart's values sit deeper and must not be mistaken for the chart's own.
	"retool/charts/postgresql/values.yaml": "image:\n  repository: bitnami/postgresql\n  tag: \"16\"\n",
}

func TestValuesReadsTheTargetChartFromAnHTTPRepository(t *testing.T) {
	archive := packChart(t, retoolChart)
	var downloads int
	mux := http.NewServeMux()
	// Relative URLs, as Helm allows, resolved against the repository URL. Served
	// under /charts so they have something to be relative to.
	mux.HandleFunc("/charts/index.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("entries:\n  retool:\n    - version: 6.11.32\n      urls: [retool-6.11.32.tgz]\n    - version: 6.11.33\n      urls: [retool-6.11.33.tgz]\n"))
	})
	mux.HandleFunc("/charts/retool-6.11.33.tgz", func(w http.ResponseWriter, _ *http.Request) {
		downloads++
		_, _ = w.Write(archive)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewHelmChecker()
	ref := ChartRef{RepoURL: srv.URL + "/charts", Name: "retool", Version: "6.11.32"}
	up, err := c.Check(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	values, err := c.Values(context.Background(), ref, up.Latest)
	if err != nil {
		t.Fatal(err)
	}
	dp, _ := values["devicePlugin"].(map[string]any)
	image, _ := dp["image"].(map[string]any)
	if image["tag"] != "v1.20.12" {
		t.Errorf("values = %v, want the chart's own values.yaml", values)
	}
	if downloads != 1 {
		t.Errorf("chart downloaded %d times, want once", downloads)
	}
}

func TestValuesWithoutACheckFirstReadsTheIndex(t *testing.T) {
	archive := packChart(t, retoolChart)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.yaml":
			_, _ = w.Write([]byte("entries:\n  retool:\n    - version: 6.11.33\n      urls: [\"http://" + r.Host + "/dl/retool.tgz\"]\n"))
		case "/dl/retool.tgz":
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	values, err := NewHelmChecker().Values(context.Background(), ChartRef{RepoURL: srv.URL, Name: "retool"}, "6.11.33")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := values["image"]; !ok {
		t.Errorf("values = %v", values)
	}
}

func TestValuesReadsAnOCIChart(t *testing.T) {
	archive := packChart(t, retoolChart)
	var asked string
	c := NewHelmChecker()
	c.ociChart = func(_ context.Context, ref string) (io.ReadCloser, error) {
		asked = ref
		return io.NopCloser(bytes.NewReader(archive)), nil
	}
	values, err := c.Values(context.Background(), ChartRef{RepoURL: "oci://registry.example.com/charts/", Name: "retool"}, "6.11.33")
	if err != nil {
		t.Fatal(err)
	}
	if asked != "registry.example.com/charts/retool:6.11.33" {
		t.Errorf("asked for %q", asked)
	}
	if _, ok := values["devicePlugin"]; !ok {
		t.Errorf("values = %v", values)
	}
}

func TestValuesFailsClearly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		archive []byte
		want    string
	}{
		{"not gzip", []byte("not a chart"), "open chart archive"},
		{"no values.yaml", packChart(t, map[string]string{"x/Chart.yaml": "name: x\n"}), "no values.yaml"},
		{"values.yaml only in a subchart", packChart(t, map[string]string{"x/charts/y/values.yaml": "a: 1\n"}), "no values.yaml"},
		{"values.yaml does not parse", packChart(t, map[string]string{"x/values.yaml": "a: [\n"}), "parse values.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := valuesFromArchive(bytes.NewReader(tc.archive))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestChartURL(t *testing.T) {
	for _, tc := range []struct{ repo, entry, want string }{
		{"https://charts.example.com", "app-1.0.0.tgz", "https://charts.example.com/app-1.0.0.tgz"},
		{"https://example.com/charts/", "app-1.0.0.tgz", "https://example.com/charts/app-1.0.0.tgz"},
		{"https://example.com/charts", "https://cdn.example.com/app.tgz", "https://cdn.example.com/app.tgz"},
	} {
		got, err := chartURL(tc.repo, tc.entry)
		if err != nil || got != tc.want {
			t.Errorf("chartURL(%q, %q) = %q, %v; want %q", tc.repo, tc.entry, got, err, tc.want)
		}
	}
}
