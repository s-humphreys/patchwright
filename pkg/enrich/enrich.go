// Package enrich augments occurrences with signals gathered outside the
// scanner export — most importantly whether an image is actually running in a
// cluster right now (live reconciliation). Enrichers run over the raw
// occurrences before dedupe, so their signals roll up into findings and become
// available to policy rules.
package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
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

// PartialLiveSource is a LiveSource that can say its read was incomplete: it saw
// every running pod but was refused some of the workload definitions, so an image
// it did not report may still be deployed and merely have no pod at the moment.
// Optional, like LabelSource; a source that does not implement it is complete.
type PartialLiveSource interface {
	RunningImagesPartial(ctx context.Context) (running map[string]int, partial bool, err error)
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

// Int returns the value for key as a non-negative integer, or 0 when it is absent or
// unparseable.
//
// Unparseable reads as absent rather than as an error: an option is a tuning knob, and
// a typo in one should leave the default in place rather than refuse to start an
// assessment. Callers treat 0 as "not set".
func (o Options) Int(key string) int {
	n, err := strconv.Atoi(strings.TrimSpace(o[key]))
	if err != nil || n < 0 {
		return 0
	}
	return n
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
// Reconciled, so policy can distinguish "not running" from "liveness unknown",
// except when the source reports a partial read (see Enrich).
type Liveness struct {
	Source LiveSource
}

// NewLiveness builds a Liveness enricher from a source.
func NewLiveness(src LiveSource) Liveness { return Liveness{Source: src} }

// Enrich implements Enricher.
//
// On a partial read, an image the source saw is still live, but one it did not see
// is left unreconciled rather than marked not running. Absence only means "not
// deployed" when every place a deployed image can be recorded was read; without the
// workload definitions a CronJob between runs looks exactly like a deleted one, and
// "not running" is what closes tickets. Unreconciled is the existing "liveness
// unknown" state, which policy treats as live and the ticket reconciler never closes
// as not running.
func (l Liveness) Enrich(ctx context.Context, occurrences []model.Occurrence) error {
	running, partial, err := l.runningImages(ctx)
	if err != nil {
		return fmt.Errorf("live source %q: %w", l.Source.Name(), err)
	}
	live, unknown := 0, 0
	for i := range occurrences {
		isLive := running[occurrences[i].Image.NameTag()] > 0
		occurrences[i].Live = isLive
		occurrences[i].Reconciled = isLive || !partial
		switch {
		case isLive:
			live++
		case partial:
			unknown++
		}
	}
	if partial {
		slog.WarnContext(ctx, "liveness read was partial; images not seen running are left unreconciled, "+
			"so nothing is judged not running this run", "source", l.Source.Name(),
			"occurrences_unreconciled", unknown)
	}
	slog.DebugContext(ctx, "reconciled liveness", "source", l.Source.Name(),
		"running_images", len(running), "occurrences", len(occurrences), "live", live, "partial", partial)
	return nil
}

func (l Liveness) runningImages(ctx context.Context) (map[string]int, bool, error) {
	if p, ok := l.Source.(PartialLiveSource); ok {
		return p.RunningImagesPartial(ctx)
	}
	running, err := l.Source.RunningImages(ctx)
	return running, false, err
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
	slog.DebugContext(ctx, "gathered namespace labels", "namespaces", len(nsLabels))
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
