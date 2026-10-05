package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Versions are ordered numerically, never lexically: 10.0.10 is newer than 10.0.9 and
// 10.0.1, whatever order the registry lists them in, and the variant family of the
// running tag is kept.
func TestNewestWithinOrdersVersionsNumerically(t *testing.T) {
	cases := []struct {
		name, current, strategy string
		tags                    []string
		want                    string
	}{
		{"double-digit patch", "10.0.1", "latest",
			[]string{"10.0.10", "10.0.9", "10.0.2", "10.0.1"}, "10.0.10"},
		{"double-digit patch listed lexically", "10.0.0", "patch",
			[]string{"10.0.0", "10.0.1", "10.0.10", "10.0.11", "10.0.2", "10.0.9"}, "10.0.11"},
		{"variant suffix kept", "10.0.1-azurelinux3.0", "latest",
			[]string{"10.0.10-azurelinux3.0", "10.0.9-azurelinux3.0", "10.0.12", "10.0.12-noble",
				"10.0.12-azurelinux3.0-distroless", "10.0.11-azurelinux3.0-amd64"}, "10.0.10-azurelinux3.0"},
		{"slim variant", "3.12.3-slim", "patch",
			[]string{"3.12.9-slim", "3.12.15-slim", "3.12.10-slim", "3.12.15", "3.13.1-slim"}, "3.12.15-slim"},
		{"v prefix", "1.9.0-noble", "latest",
			[]string{"v1.9.0-noble", "v1.10.0-noble", "v1.63.0-noble", "v1.100.0-jammy"}, "v1.63.0-noble"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pick(t, c.current, c.strategy, "", c.tags); got != c.want {
				t.Errorf("picked %q, want %q", got, c.want)
			}
		})
	}
}

// A repository with thousands of tags is listed across pages, and a tag on a later
// page is as much a candidate as one on the first. The registry lister follows the
// Link header to the end.
func TestTagListerFollowsPagination(t *testing.T) {
	var all []string
	for i := 0; i <= 12; i++ {
		all = append(all, fmt.Sprintf("10.0.%d", i))
	}
	const pageSize = 5
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/v2/runtime/tags/list":
			pages++
			start, _ := strconv.Atoi(r.URL.Query().Get("last"))
			end := min(start+pageSize, len(all))
			if end < len(all) {
				w.Header().Set("Link", fmt.Sprintf(`</v2/runtime/tags/list?last=%d>; rel="next"`, end))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "runtime", "tags": all[start:end]})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tags, err := NewTagLister().Tags(context.Background(), strings.TrimPrefix(srv.URL, "http://")+"/runtime")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != len(all) || pages < 3 {
		t.Fatalf("listed %d tags over %d pages, want %d over 3", len(tags), pages, len(all))
	}
	if got := pick(t, "10.0.1", "latest", "", tags); got != "10.0.12" {
		t.Errorf("picked %q from a paginated listing, want 10.0.12", got)
	}
}
