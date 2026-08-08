// Package enrich augments occurrences with signals gathered outside the
// scanner export — most importantly whether an image is actually running in a
// cluster right now (live reconciliation). Enrichers run over the raw
// occurrences before dedupe, so their signals roll up into findings and become
// available to policy rules.
package enrich

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// Enricher augments a batch of occurrences in place.
type Enricher interface {
	Enrich(ctx context.Context, occurrences []model.Occurrence) error
}

// LiveSource reports the images currently running across one or more clusters.
// Implementations include a file-based snapshot (for testing and offline demos)
// and a client-go reader over live clusters. The returned map is keyed by image
// "registry/repository:tag" (see model.Image.NameTag) with the count of running
// workloads using each image.
type LiveSource interface {
	Name() string
	RunningImages(ctx context.Context) (map[string]int, error)
}

// LabelSource reports namespace labels across one or more clusters, keyed by
// namespace name. It backs ownership attribution from labels such as "team".
// A LiveSource may optionally also implement LabelSource (the client-go kube
// source does); the offline file source does not.
type LabelSource interface {
	NamespaceLabels(ctx context.Context) (map[string]map[string]string, error)
}

// Options is source-specific configuration, interpreted by each LiveSource.
type Options map[string]string

// String returns the value for key, or "" if absent.
func (o Options) String(key string) string { return o[key] }

// StringOr returns the value for key, or def if absent or empty.
func (o Options) StringOr(key, def string) string {
	if v, ok := o[key]; ok && v != "" {
		return v
	}
	return def
}

// Factory constructs a LiveSource from Options.
type Factory func(opts Options) (LiveSource, error)

var registry = map[string]Factory{}

// Register makes a live source available by name (called from init functions).
func Register(name string, f Factory) {
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("enrich: live source %q already registered", name))
	}
	registry[name] = f
}

// NewLiveSource constructs a registered live source by name.
func NewLiveSource(name string, opts Options) (LiveSource, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown live source %q (available: %s)", name, strings.Join(LiveSourceNames(), ", "))
	}
	return f(opts)
}

// LiveSourceNames returns the sorted registered live source names.
func LiveSourceNames() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Liveness is an Enricher that marks each occurrence live or not by matching
// its image against a LiveSource. Every occurrence it touches is marked
// Reconciled, so policy can distinguish "not running" from "liveness unknown".
type Liveness struct {
	Source LiveSource
}

// NewLiveness builds a Liveness enricher from a source.
func NewLiveness(src LiveSource) Liveness { return Liveness{Source: src} }

// Enrich implements Enricher.
func (l Liveness) Enrich(ctx context.Context, occurrences []model.Occurrence) error {
	running, err := l.Source.RunningImages(ctx)
	if err != nil {
		return fmt.Errorf("live source %q: %w", l.Source.Name(), err)
	}
	for i := range occurrences {
		occurrences[i].Reconciled = true
		occurrences[i].Live = running[occurrences[i].Image.NameTag()] > 0
	}
	return nil
}

// NamespaceLabeler is an Enricher that attaches namespace labels (e.g.
// "team") to each occurrence based on its namespace dimension. It never
// overwrites a label already present on the occurrence, so a more specific
// source (e.g. workload labels) takes precedence. Attaching labels lets
// ownership rules attribute by label rather than namespace-name heuristics.
type NamespaceLabeler struct {
	Source LabelSource
	// Dimension names the occurrence dimension holding the namespace.
	// Defaults to "namespace" when empty.
	Dimension string
}

// NewNamespaceLabeler builds a NamespaceLabeler from a source.
func NewNamespaceLabeler(src LabelSource) NamespaceLabeler {
	return NamespaceLabeler{Source: src, Dimension: "namespace"}
}

// Enrich implements Enricher.
func (n NamespaceLabeler) Enrich(ctx context.Context, occurrences []model.Occurrence) error {
	nsLabels, err := n.Source.NamespaceLabels(ctx)
	if err != nil {
		return fmt.Errorf("namespace labels: %w", err)
	}
	dim := n.Dimension
	if dim == "" {
		dim = "namespace"
	}
	for i := range occurrences {
		ns := occurrences[i].Resource.Dimensions[dim]
		labels := nsLabels[ns]
		if len(labels) == 0 {
			continue
		}
		if occurrences[i].Resource.Labels == nil {
			occurrences[i].Resource.Labels = make(map[string]string, len(labels))
		}
		for k, v := range labels {
			if _, exists := occurrences[i].Resource.Labels[k]; !exists {
				occurrences[i].Resource.Labels[k] = v
			}
		}
	}
	return nil
}
