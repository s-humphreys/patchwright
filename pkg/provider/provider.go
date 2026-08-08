// Package provider defines the pluggable ingestion layer. A Provider supplies
// vulnerability scan data, translating a specific scanner's output (Rapid7,
// Trivy, Grype, ...) into patchwright's generic model. All vendor-specific
// parsing lives behind this interface so the rest of the pipeline stays
// scanner-agnostic. Providers register themselves by name and are constructed
// via New, so adding a scanner is additive — no core changes required.
package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/s-humphreys/patchwright/pkg/model"
)

// Provider is a source of vulnerability scan data.
type Provider interface {
	// Name returns the provider's registered identifier, e.g. "rapid7".
	Name() string
	// Fetch returns the provider's normalized occurrences.
	Fetch(ctx context.Context) ([]model.Occurrence, error)
}

// Options is provider-specific configuration passed at construction. Keys are
// interpreted by each provider (e.g. the rapid7 provider reads "input" for a
// CSV path and "mode" for csv|api).
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

// Factory constructs a Provider from Options.
type Factory func(opts Options) (Provider, error)

var registry = map[string]Factory{}

// Register makes a provider available by name. Providers call this from an
// init function. It panics on duplicate registration, which can only be a
// programming error.
func Register(name string, f Factory) {
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("provider: %q already registered", name))
	}
	registry[name] = f
}

// New constructs a registered provider by name.
func New(name string, opts Options) (Provider, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	return f(opts)
}

// Names returns the sorted list of registered provider names.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
