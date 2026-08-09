// Package config defines patchwright's declarative rule configuration and
// loads it from YAML. Rules are written by users — security and platform
// engineers alike — and interpreted as CEL expressions over the generic model,
// so no organization-specific taxonomy is baked into the tool.
package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the complete rule set. Ownership rules attribute each occurrence to
// an owner; policy rules (actionable/suppress) decide what to act on.
type Config struct {
	// Owners are evaluated in order against each occurrence; the first whose
	// Match expression is true wins.
	Owners []OwnerRule `yaml:"owners"`
	// Actionable rules mark a finding for action and assign a priority; the
	// first matching rule wins.
	Actionable []PolicyRule `yaml:"actionable"`
	// Suppress rules drop a finding from the actionable set (e.g. accepted
	// risk, known false positive). Suppression takes precedence over
	// actionability.
	Suppress []PolicyRule `yaml:"suppress"`
	// Scan tunes image vulnerability scanning.
	Scan ScanConfig `yaml:"scan"`
}

// ScanConfig tunes which images are worth scanning for vulnerabilities.
type ScanConfig struct {
	// SkipOwnerClasses lists owner classes whose images are not scanned —
	// typically ones you can't remediate and already suppress (e.g.
	// cloud-provider-managed images). An image is skipped only if every one of
	// its workloads is owned by a skipped class.
	//
	// Unset defaults to ["cloud-provider"]; set to [] to scan everything.
	SkipOwnerClasses []string `yaml:"skipOwnerClasses"`
}

// EffectiveSkipOwnerClasses returns the configured skip list, or the default
// (["cloud-provider"]) when the field is unset. An explicit empty list scans
// everything.
func (s ScanConfig) EffectiveSkipOwnerClasses() []string {
	if s.SkipOwnerClasses == nil {
		return []string{"cloud-provider"}
	}
	return s.SkipOwnerClasses
}

// OwnerRule attributes a resource to an owner. Match is a CEL boolean over the
// occurrence context (image, dimensions, labels, counts, resource). Team is a
// literal owner; TeamFrom, when set, is a CEL string expression evaluated
// against the same context (e.g. "labels['team']" or "dimensions['namespace']")
// and takes precedence over Team.
type OwnerRule struct {
	Name     string `yaml:"name"`
	Match    string `yaml:"match"`
	Class    string `yaml:"class"`
	Team     string `yaml:"team"`
	TeamFrom string `yaml:"teamFrom"`
}

// PolicyRule is a named CEL boolean over the finding context. Priority is a
// free-form label applied when an actionable rule matches (ignored for
// suppress rules).
type PolicyRule struct {
	Name     string `yaml:"name"`
	When     string `yaml:"when"`
	Priority string `yaml:"priority"`
}

// Load reads and merges one or more YAML config files. Later files append to
// earlier ones, so configuration can be split across files (e.g. ownership.yaml
// and policy.yaml).
func Load(paths ...string) (*Config, error) {
	cfg := &Config{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", p, err)
		}
		var part Config
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&part); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", p, err)
		}
		cfg.Owners = append(cfg.Owners, part.Owners...)
		cfg.Actionable = append(cfg.Actionable, part.Actionable...)
		cfg.Suppress = append(cfg.Suppress, part.Suppress...)
		// scan is a singleton section; the last file that sets it wins.
		if part.Scan.SkipOwnerClasses != nil {
			cfg.Scan = part.Scan
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	slog.Debug("loaded config", "files", len(paths),
		"owner_rules", len(cfg.Owners), "actionable_rules", len(cfg.Actionable), "suppress_rules", len(cfg.Suppress))
	return cfg, nil
}

// validate checks structural invariants that are independent of CEL
// compilation (which the attribution and policy engines perform).
func (c *Config) validate() error {
	seen := map[string]bool{}
	for _, r := range c.Owners {
		if r.Name == "" {
			return fmt.Errorf("owner rule missing name")
		}
		if r.Match == "" {
			return fmt.Errorf("owner rule %q missing match expression", r.Name)
		}
		if seen["owner/"+r.Name] {
			return fmt.Errorf("duplicate owner rule name %q", r.Name)
		}
		seen["owner/"+r.Name] = true
	}
	for _, r := range c.Actionable {
		if err := validatePolicyRule("actionable", r, seen); err != nil {
			return err
		}
	}
	for _, r := range c.Suppress {
		if err := validatePolicyRule("suppress", r, seen); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyRule(kind string, r PolicyRule, seen map[string]bool) error {
	if r.Name == "" {
		return fmt.Errorf("%s rule missing name", kind)
	}
	if r.When == "" {
		return fmt.Errorf("%s rule %q missing when expression", kind, r.Name)
	}
	key := kind + "/" + r.Name
	if seen[key] {
		return fmt.Errorf("duplicate %s rule name %q", kind, r.Name)
	}
	seen[key] = true
	return nil
}
