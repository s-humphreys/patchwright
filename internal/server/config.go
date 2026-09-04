package server

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/s-humphreys/patchwright/internal/mcp"
	"github.com/s-humphreys/patchwright/pkg/config"
)

// Serving the loaded rules back.
//
// "Why is this finding not actionable?" and "who does this namespace belong to?"
// are answered by the rules, and the rules usually live in a repository the person
// asking cannot see — or in a ConfigMap they would need cluster access to read. The
// answer is one request away from the data it explains, so it may as well be here.
//
// What is served is the text that was parsed at startup, not the files as they are
// now. Re-reading them would show edits that are not in effect, which is a worse
// answer than none.

// configSource is one config file as the API reports it.
type configSource struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	// Redacted is true when a value in this file was withheld.
	Redacted bool `json:"redacted,omitempty"`
}

// WithConfig attaches the loaded configuration so it can be served, so lapsed
// suppressions can be reported, and so a policy report can list the rules that
// matched nothing.
func (s *Server) WithConfig(cfg *config.Config) *Server {
	if cfg != nil {
		s.configSources = cfg.Sources
		s.suppressRules = cfg.Suppress
		s.actionableRules = cfg.Actionable
	}
	return s
}

// policyRules translates the loaded rules for the MCP tools.
//
// A translation rather than handing over config.PolicyRule, for the same reason
// ticketsForAnalytics is one: the tool payload is a published contract, and coupling
// it to the config struct would let a YAML field rename change a tool's output.
func (s *Server) policyRules() mcp.PolicyRules {
	out := mcp.PolicyRules{}
	for _, r := range s.actionableRules {
		out.Actionable = append(out.Actionable, mcp.PolicyRuleDef{
			Name: r.Name, When: r.When, Priority: r.Priority,
		})
	}
	for _, r := range s.suppressRules {
		out.Suppress = append(out.Suppress, mcp.PolicyRuleDef{
			Name: r.Name, When: r.When, Until: r.Until,
		})
	}
	return out
}

// expiredSuppressions lists the suppress rules that have lapsed.
//
// Computed from the configuration and the clock rather than carried through the
// assessment, because that is all it depends on — and because it must be reportable
// even on a run where nothing happened to match the lapsed rule.
func (s *Server) expiredSuppressions() []expiredRule {
	now := time.Now()
	var out []expiredRule
	for _, r := range s.suppressRules {
		if r.Expired(now) {
			out = append(out, expiredRule{Name: r.Name, Until: r.Until})
		}
	}
	return out
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if len(s.configSources) == 0 {
		// Distinguishes "no config was loaded" from "config is empty", which read
		// the same in a viewer showing nothing.
		writeError(w, http.StatusNotFound, "no configuration was loaded")
		return
	}
	out := make([]configSource, 0, len(s.configSources))
	for _, src := range s.configSources {
		content, redacted := redactSecrets(src.Content)
		out = append(out, configSource{Path: src.Path, Content: content, Redacted: redacted})
	}
	writeJSON(w, http.StatusOK, struct {
		Sources []configSource `json:"sources"`
	}{out})
}

// secretish matches a YAML key whose value should never be shown.
//
// Credentials are read from the environment by design, so nothing here should ever
// match. That is exactly why it exists: this endpoint turns a config file into an
// HTTP response, and the cost of being wrong about what someone put in one is a
// credential in a browser tab. Belt and braces, cheap.
var secretish = regexp.MustCompile(`(?i)^(\s*(?:-\s+)?)([a-z0-9_-]*(?:token|password|passwd|secret|apikey|api_key|credential|private_key)[a-z0-9_-]*)(\s*:\s*)(.+)$`)

// redactSecrets replaces the value of any secret-looking key, reporting whether it
// changed anything.
func redactSecrets(content string) (string, bool) {
	var redacted bool
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		m := secretish.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// An empty value or a comment-only remainder is not a secret, and blanking
		// it would suggest one had been set.
		value := strings.TrimSpace(m[4])
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		lines[i] = m[1] + m[2] + m[3] + "[redacted]"
		redacted = true
	}
	if !redacted {
		return content, false
	}
	return strings.Join(lines, "\n"), true
}
