// Package metrics exposes patchwright's state and failures to Prometheus.
//
// Two kinds of thing are worth alerting on, and they are not the same kind:
//
//   - Coverage. "How much of the estate does anyone actually have data for" is the
//     question this tool exists to answer, and it degrades silently. A registry
//     credential expiring somewhere else turns 96% of an estate into zeros that
//     look like clean results, and nothing about the service itself looks unwell.
//   - Failures. Credentials expire, APIs reject writes, scanners cannot pull
//     images. These are ordinary operational faults and want ordinary counters.
//
// Everything is on a registry owned here rather than the global default, so
// nothing can register into patchwright's namespace as a side effect of an
// import, and a test can assert the whole surface.
//
// Cardinality is bounded deliberately. There is no per-image or per-CVE label
// anywhere: an estate of 800 images would put 800 series behind one metric, and
// the queue already has a JSON API for questions at that grain. Labels are owner
// class, team, and small closed sets like an action kind.
package metrics

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Namespace prefixes every metric. Enforced by a test rather than by convention.
const Namespace = "patchwright"

var registry = prometheus.NewRegistry()

// gauge, gaugeVec and counterVec construct a collector in patchwright's namespace
// and register it. Registration happens here rather than in init so a metric
// cannot be declared and then forgotten — the declaration is the registration.
func gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: Namespace, Name: name, Help: help})
	registry.MustRegister(g)
	return g
}

func gaugeVec(name, help string, labels []string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: Namespace, Name: name, Help: help}, labels)
	registry.MustRegister(g)
	return g
}

func counterVec(name, help string, labels []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: Namespace, Name: name, Help: help}, labels)
	registry.MustRegister(c)
	return c
}

// Assessment health: did the run work, when did it last work, and how old is the
// data underneath it.
var (
	assessmentRuns = counterVec("assessment_runs_total",
		"Assessments attempted, by outcome.", []string{"result"})

	assessmentDuration = gauge("assessment_duration_seconds",
		"Duration of the most recent completed assessment.")

	assessmentLastSuccess = gauge("assessment_last_success_timestamp_seconds",
		"Unix time of the last assessment that produced a usable result.")

	// providerDataAge is the metric to alert on, and the one whose absence hid a
	// week-old export behind a freshly-generated report. It measures the scan
	// provider's own timestamps, not ours: a service refreshing hourly over a
	// stale file reports a healthy assessment of ancient data forever. -1 means
	// the provider reported no timestamps at all, which is not the same as fresh.
	providerDataAge = gauge("provider_data_age_seconds",
		"Age of the newest assessment timestamp in the scan provider's own data, "+
			"or -1 when the provider reported none.")
)

// Coverage and queue shape, from the latest cached assessment.
var (
	findings = gauge("findings", "Unsuppressed findings in the latest assessment.")

	findingsByState = gaugeVec("findings_by_state",
		"Findings by what is known about them. Absent data and zero are different "+
			"states: provider_unassessed means nobody looked, not that nothing was found.",
		[]string{"state"})

	uniqueImages = gauge("images_unique",
		"Distinct images across all findings, suppressed included.")

	// Per owner. Bounded by the number of teams, which is small and changes rarely.
	ownerFindings = gaugeVec("owner_findings",
		"Findings per owner, by state.", []string{"class", "team", "state"})

	// unassessedReasons turns a coverage gap into something alertable by cause. On
	// a real estate one reason accounted for nearly all of it, and a percentage
	// could not say which.
	unassessedReasons = gaugeVec("findings_unassessed_by_reason",
		"Findings the scan provider did not assess, by its stated reason.",
		[]string{"reason"})
)

// Failures.
var (
	jiraRequests = counterVec("jira_requests_total",
		"Jira API requests by operation and outcome. auth_error is separated from "+
			"other failures because expired or wrong credentials are the common cause "+
			"and need a different response from a transient fault.",
		[]string{"operation", "outcome"})

	ticketActions = counterVec("ticket_actions_total",
		"Ticket reconciliation actions by kind and result. noop is separate from "+
			"applied: a comment that was already present is not a write.",
		[]string{"action", "result"})

	imageScans = counterVec("image_scans_total",
		"Image scans attempted by the optional vulnerability scanner, by result.",
		[]string{"result"})

	providerFetches = counterVec("provider_fetches_total",
		"Fetches of scan data from the provider, by outcome.", []string{"result"})
)

func init() {
	// Go runtime and process metrics. Operators expect them, and a memory leak in
	// a long-running service is not visible from domain metrics alone.
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// Handler serves the registry in Prometheus text format.
//
// Deliberately not the global default registry's handler: this exposes only what
// patchwright registers plus the runtime collectors above.
func Handler() http.Handler {
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		// A broken collector should not blank the whole scrape.
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// Registry exposes the registry for tests that assert the exported surface.
func Registry() *prometheus.Registry { return registry }

// AssessmentStarted returns a function to call when the assessment finishes,
// which records its duration and outcome. Written this way so a caller cannot
// record a result without a duration or the reverse.
func AssessmentStarted() func(err error) {
	start := time.Now()
	return func(err error) {
		assessmentDuration.Set(time.Since(start).Seconds())
		if err != nil {
			assessmentRuns.WithLabelValues("failure").Inc()
			return
		}
		assessmentRuns.WithLabelValues("success").Inc()
		assessmentLastSuccess.Set(float64(time.Now().Unix()))
	}
}

// Snapshot is the state of one completed assessment, as metrics see it. A struct
// rather than a long parameter list so adding a measure cannot silently shift
// existing arguments.
type Snapshot struct {
	Findings           int
	Actionable         int
	Suppressed         int
	ProviderAssessed   int
	ProviderUnassessed int
	Scanned            int
	ExploitChecked     int
	Upgradable         int
	KnownExploited     int
	RemediationUnknown int
	ActionableBlind    int
	UniqueImages       int

	// ProviderDataNewest is the newest assessment time in the provider's data.
	// Zero means nothing carried one, and the age metric is then not published
	// rather than published as a huge number that would fire every alert.
	ProviderDataNewest time.Time

	Owners  []OwnerSnapshot
	Reasons []ReasonCount
}

// OwnerSnapshot is one team's slice of the queue.
type OwnerSnapshot struct {
	Class      string
	Team       string
	Findings   int
	Actionable int
	Unassessed int
	Ticketed   int
}

// ReasonCount is a stated reason for missing coverage and how much it costs.
type ReasonCount struct {
	Reason   string
	Findings int
}

// maxReasons bounds the reason label. Reasons are provider-supplied strings, so
// an unlucky provider could otherwise mint a new label value per image; the tail
// is summed into "other" rather than dropped, so the total still adds up.
const maxReasons = 10

var (
	// mu guards the published label sets. Gauges are reset between snapshots so a
	// team or reason that disappears stops being reported rather than freezing at
	// its last value, which would be a lie that never expires.
	mu sync.Mutex
)

// Observe publishes a completed assessment.
func Observe(s Snapshot) {
	mu.Lock()
	defer mu.Unlock()

	findings.Set(float64(s.Findings))
	uniqueImages.Set(float64(s.UniqueImages))

	for state, n := range map[string]int{
		"actionable":            s.Actionable,
		"suppressed":            s.Suppressed,
		"provider_assessed":     s.ProviderAssessed,
		"provider_unassessed":   s.ProviderUnassessed,
		"scanned":               s.Scanned,
		"exploit_checked":       s.ExploitChecked,
		"upgradable":            s.Upgradable,
		"known_exploited":       s.KnownExploited,
		"remediation_unknown":   s.RemediationUnknown,
		"actionable_unassessed": s.ActionableBlind,
	} {
		findingsByState.WithLabelValues(state).Set(float64(n))
	}

	// Reset before republishing: an owner or reason that has gone away must stop
	// being exported, not linger at its final value.
	ownerFindings.Reset()
	for _, o := range s.Owners {
		team := o.Team
		if team == "" {
			// An empty label is indistinguishable from an absent one in most
			// dashboards, and "no rule attributed this" is a real state worth
			// seeing rather than a blank row.
			team = "unattributed"
		}
		for state, n := range map[string]int{
			"total":      o.Findings,
			"actionable": o.Actionable,
			"unassessed": o.Unassessed,
			"ticketed":   o.Ticketed,
		} {
			ownerFindings.WithLabelValues(o.Class, team, state).Set(float64(n))
		}
	}

	unassessedReasons.Reset()
	for reason, n := range foldReasons(s.Reasons) {
		unassessedReasons.WithLabelValues(reason).Set(float64(n))
	}

	if s.ProviderDataNewest.IsZero() {
		// Not published at all. A zero timestamp would compute to decades of age
		// and fire every staleness alert on an estate that simply does not report
		// assessment times.
		providerDataAge.Set(-1)
		return
	}
	providerDataAge.Set(time.Since(s.ProviderDataNewest).Seconds())
}

// foldReasons normalises reason text into label values and caps the count.
func foldReasons(reasons []ReasonCount) map[string]int {
	sorted := make([]ReasonCount, len(reasons))
	copy(sorted, reasons)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Findings > sorted[j].Findings })

	out := map[string]int{}
	for i, r := range sorted {
		if i >= maxReasons {
			out["other"] += r.Findings
			continue
		}
		out[normalizeReason(r.Reason)] += r.Findings
	}
	return out
}

// normalizeReason shortens a provider's sentence into a stable label.
//
// Providers embed specifics in these strings (an image name, a digest), and each
// variant would otherwise be its own series. The first sentence is the stable,
// diagnostic part: "Can't authenticate to ACR" rather than the digest that
// failed.
func normalizeReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "unknown"
	}
	if i := strings.IndexAny(reason, ".:"); i > 0 {
		reason = reason[:i]
	}
	const maxLen = 80
	if len(reason) > maxLen {
		reason = strings.TrimSpace(reason[:maxLen])
	}
	return reason
}

// JiraRequest records the outcome of a Jira call. status is the HTTP status, 0
// when the request never got a response.
func JiraRequest(operation string, status int, err error) {
	jiraRequests.WithLabelValues(operation, jiraOutcome(status, err)).Inc()
}

// jiraOutcome classifies a Jira result into a small closed set.
//
// auth_error is separated on purpose: an expired token, a revoked account or a
// wrong email all surface as 401/403, and that needs a person rather than a
// retry. Lumping it into client_error would bury the single most likely reason
// ticketing silently stops working.
func jiraOutcome(status int, err error) string {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return "auth_error"
	case status == http.StatusTooManyRequests:
		return "rate_limited"
	case status >= 500:
		return "server_error"
	case status >= 400:
		return "client_error"
	case err != nil:
		// No status at all: DNS, TLS, timeout. Distinct from a rejection, because
		// the fix is somewhere else entirely.
		return "network_error"
	default:
		return "ok"
	}
}

// TicketAction records one reconciliation action's result. result is "applied",
// "noop" or "failed".
func TicketAction(action, result string) {
	ticketActions.WithLabelValues(action, result).Inc()
}

// ImageScan records one image scan attempt: "ok", "failed" or "skipped".
func ImageScan(result string) { imageScans.WithLabelValues(result).Inc() }

// ProviderFetch records a fetch of scan data: "success" or "failure".
func ProviderFetch(result string) { providerFetches.WithLabelValues(result).Inc() }
