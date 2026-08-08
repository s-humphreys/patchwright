// Package file implements a file-based LiveSource: a snapshot of the images
// currently running in a cluster, one image reference per line. It is used for
// unit tests, offline demos, and air-gapped environments where the tool cannot
// reach the clusters directly.
//
// A snapshot can be produced from a live cluster with, for example:
//
//	kubectl get pods -A \
//	  -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' \
//	  | sort -u > live-images.txt
//
// Blank lines and lines beginning with '#' are ignored.
package file

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func init() {
	enrich.Register("file", func(opts enrich.Options) (enrich.LiveSource, error) {
		path := opts.String("path")
		if path == "" {
			return nil, fmt.Errorf("file live source requires option \"path\"")
		}
		return &source{path: path}, nil
	})
}

type source struct {
	path string
}

func (s *source) Name() string { return "file" }

func (s *source) RunningImages(ctx context.Context) (map[string]int, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("open live snapshot: %w", err)
	}
	defer f.Close()

	running := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Normalize each ref the same way scanner findings are, so matching is
		// on registry/repository:tag regardless of how the ref was written.
		running[model.ParseImageRef(line).NameTag()]++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read live snapshot: %w", err)
	}
	return running, nil
}
