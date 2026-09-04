package trivy

import "testing"

// A handled single-image timeout must not read like the scanner crashed. Trivy's
// stderr contains "FATAL Fatal error", which reproduced verbatim inside our WARN
// line got reported as an outage.
func TestScanFailureReasonStripsTrivysFatalBanner(t *testing.T) {
	stderr := "2026-08-11T09:08:31+01:00\tFATAL\tFatal error\trun error: image scan error: " +
		"scan error: scan failed: failed analysis: analyze error: pipeline error: " +
		"failed to analyze layer (sha256:4e96): walk error: failed to process the file: " +
		"failed to analyze file: failed to analyze usr/local/lib/x.wasm: " +
		"semaphore acquire: context deadline exceeded"

	got := scanFailureReason(stderr)
	for _, unwanted := range []string{"FATAL", "Fatal error", "2026-08-11T09"} {
		if contains(got, unwanted) {
			t.Errorf("reason still contains %q: %s", unwanted, got)
		}
	}
	if !contains(got, "context deadline exceeded") {
		t.Errorf("reason lost the actual cause: %s", got)
	}
}

func TestScanFailureReasonHandlesEmptyAndPlainOutput(t *testing.T) {
	if got := scanFailureReason("   \n  "); got != "no output" {
		t.Errorf("empty stderr: got %q", got)
	}
	if got := scanFailureReason("unauthorized: authentication required"); got == "" {
		t.Errorf("plain error was emptied")
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// The ACR shape: an auth failure ending in a correlation UUID. The innermost-clause
// heuristic used to pick the UUID, which reads as nothing and, once these are
// counted by cause, is one metric bucket per request.
func TestScanFailureReasonIgnoresTrailingCorrelationIDs(t *testing.T) {
	stderr := "2026-09-04T08:40:00+01:00\tFATAL\tFatal error\trun error: image scan error: " +
		"* remote error: GET https://acme.azurecr.io/oauth2/token?scope=repository%3Aapp%3Apull: " +
		"UNAUTHORIZED: authentication required, visit https://aka.ms/acr/authorization for more " +
		"information. CorrelationId: e5d7b9dc-367d-4a52-95f4-83f7f039a872"

	got := scanFailureReason(stderr)
	if contains(got, "e5d7b9dc") {
		t.Errorf("reason is a per-request identifier: %s", got)
	}
	if !contains(got, "authentication required") {
		t.Errorf("reason lost the actual cause: %s", got)
	}
}
