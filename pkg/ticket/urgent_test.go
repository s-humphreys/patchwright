package ticket

import (
	"strings"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/sink"
)

func urgentGroup(vulns ...sink.VulnView) ticketGroup {
	return ticketGroup{primary: []sink.FindingView{finding("a/svc", func(f *sink.FindingView) {
		f.Vulns = vulns
	})}}
}

// Only what made the finding urgent is listed: exploited or likely to be, and
// fixable. Exploited leads, whatever its EPSS.
func TestUrgentListsExploitedFixableCVEsExploitedFirst(t *testing.T) {
	got := urgent(urgentGroup(
		sink.VulnView{ID: "CVE-HOT", EPSS: 0.9, FixAvailable: true},
		sink.VulnView{ID: "CVE-KEV", KEV: true, EPSS: 0.01, FixAvailable: true},
		sink.VulnView{ID: "CVE-NOFIX", KEV: true, FixAvailable: false},
		sink.VulnView{ID: "CVE-QUIET", EPSS: 0.2, FixAvailable: true},
	).all(), 0)
	if len(got) != 2 {
		t.Fatalf("urgent = %+v, want CVE-KEV and CVE-HOT only", got)
	}
	if got[0].ID != "CVE-KEV" || got[1].ID != "CVE-HOT" {
		t.Errorf("order = %s, %s; exploited in the wild must lead", got[0].ID, got[1].ID)
	}
	if got[0].Why != "exploited in the wild" || got[1].Why != "EPSS 0.90" {
		t.Errorf("why = %q, %q", got[0].Why, got[1].Why)
	}
}

// A CVE is cleared only when the differential measured it, and one nothing
// measured is told apart from one the change was measured to leave.
func TestUrgentTellsClearedFromUnmeasured(t *testing.T) {
	byID := map[string]UrgentVuln{}
	for _, u := range urgent(urgentGroup(
		sink.VulnView{ID: "CVE-A", KEV: true, FixAvailable: true, Origin: "base", OriginDetermined: true, FixedByUpgrade: true},
		sink.VulnView{ID: "CVE-B", KEV: true, FixAvailable: true, Origin: "app", OriginDetermined: true},
		sink.VulnView{ID: "CVE-C", KEV: true, FixAvailable: true},
	).all(), 0) {
		byID[u.ID] = u
	}
	if a := byID["CVE-A"]; !a.Cleared || !a.Measured {
		t.Errorf("CVE-A was measured and removed: %+v", a)
	}
	if b := byID["CVE-B"]; b.Cleared || !b.Measured {
		t.Errorf("CVE-B was measured and kept: %+v", b)
	}
	if c := byID["CVE-C"]; c.Cleared || c.Measured {
		t.Errorf("CVE-C was never measured: %+v", c)
	}
	if !strings.Contains(byID["CVE-A"].Action, "Nothing extra") {
		t.Errorf("cleared row should need nothing extra: %q", byID["CVE-A"].Action)
	}
}

// "Done means" lists only what the change clears. A CVE the change leaves, or
// that nothing measured, is left off entirely, so the ticket never waits on
// something its own change cannot touch.
func TestDoneMeansListsOnlyWhatTheChangeClears(t *testing.T) {
	d := newTemplateData(urgentGroup(
		sink.VulnView{ID: "CVE-A", KEV: true, FixAvailable: true, Origin: "base", OriginDetermined: true, FixedByUpgrade: true},
		sink.VulnView{ID: "CVE-B", KEV: true, FixAvailable: true, Origin: "app", OriginDetermined: true},
		sink.VulnView{ID: "CVE-C", KEV: true, FixAvailable: true},
	), nil, 0)
	if len(d.Urgent) != 1 || d.Urgent[0].ID != "CVE-A" {
		t.Fatalf("urgent = %+v, want CVE-A alone", d.Urgent)
	}
	if d.UrgentCleared != 1 || d.UrgentUnknown != 0 || d.UrgentRemaining() != 0 || !d.UrgentAllCleared() {
		t.Errorf("legacy counts disagree with the list: cleared=%d unknown=%d remaining=%d all=%v",
			d.UrgentCleared, d.UrgentUnknown, d.UrgentRemaining(), d.UrgentAllCleared())
	}
	if d.clearsNone {
		t.Error("the change clears CVE-A, so the ticket must be raised")
	}
}

// Several deployments of one service: cleared only if cleared on all of them.
func TestUrgentIsConservativeAcrossDeployments(t *testing.T) {
	kev := func(fixed bool) sink.VulnView {
		return sink.VulnView{ID: "CVE-X", KEV: true, FixAvailable: true, Origin: "base", OriginDetermined: true, FixedByUpgrade: fixed}
	}
	g := ticketGroup{primary: []sink.FindingView{
		finding("a/svc", func(f *sink.FindingView) { f.Vulns = []sink.VulnView{kev(true)} }),
		finding("a/svc", func(f *sink.FindingView) { f.Image = "a/svc:old"; f.Vulns = []sink.VulnView{kev(false)} }),
	}}
	got := urgent(g.all(), 0)
	if len(got) != 1 || got[0].Cleared {
		t.Errorf("one deployment keeps the CVE after the upgrade, yet it reads as cleared: %+v", got)
	}
	if d := newTemplateData(g, nil, 0); len(d.Urgent) != 0 {
		t.Errorf("a CVE not cleared everywhere must not be under Done means: %+v", d.Urgent)
	}
}

// The wording is for people who build services, not distributions.
func TestUrgentAdviceReadsAsPlainEnglish(t *testing.T) {
	cases := []struct {
		name     string
		v        sink.VulnView
		where    string
		action   string
		notWhere string
	}{
		{
			name: "OS package the Dockerfile installs",
			v: sink.VulnView{ID: "CVE-1", KEV: true, FixAvailable: true, FixedVersion: "1:2.39.5", Origin: "app", OriginDetermined: true,
				Packages: []sink.PackageView{{Name: "git", Ecosystem: "debian"}}},
			where: "A Linux package your Dockerfile installs (git)", action: "apt-get upgrade",
		},
		{
			name: "kernel headers are build-only",
			v: sink.VulnView{ID: "CVE-2", KEV: true, FixAvailable: true, FixedVersion: "6.12.95-1", Origin: "app", OriginDetermined: true,
				Packages: []sink.PackageView{{Name: "linux-libc-dev", Ecosystem: "ubuntu"}}},
			where: "Kernel headers your Dockerfile installs", action: "build stage",
		},
		{
			name: "language package names its file",
			v: sink.VulnView{ID: "CVE-3", KEV: true, FixAvailable: true, FixedVersion: "1.0.1", Origin: "app", OriginDetermined: true,
				Packages: []sink.PackageView{{Name: "mcp", Ecosystem: "pip", Path: "app/requirements.txt"}}},
			where: "The Python package mcp, declared in app/requirements.txt", action: "Move mcp to 1.0.1 in app/requirements.txt",
		},
		{
			name: "language package without a recorded file falls back to the usual one",
			v: sink.VulnView{ID: "CVE-4", KEV: true, FixAvailable: true, FixedVersion: "1.84.0", Origin: "app", OriginDetermined: true,
				Packages: []sink.PackageView{{Name: "Some.Lib", Ecosystem: "nuget"}}},
			where: "The NuGet package Some.Lib, declared in the .csproj", action: "1.84.0",
		},
		{
			name:  "application CVE nothing named",
			v:     sink.VulnView{ID: "CVE-5", KEV: true, FixAvailable: true, FixedVersion: "1.0.1", Origin: "app", OriginDetermined: true},
			where: "no scan named it", action: "below 1.0.1",
		},
		{
			name: "base still carries it after the upgrade",
			v: sink.VulnView{ID: "CVE-6", KEV: true, FixAvailable: true, FixedVersion: "3.0", Origin: "base", OriginDetermined: true,
				Packages: []sink.PackageView{{Name: "openssl", Ecosystem: "azurelinux"}}},
			where: "The base image (openssl)", action: "newer base still carries it",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := urgent(urgentGroup(tc.v).all(), 0)
			if len(got) != 1 {
				t.Fatalf("urgent = %+v", got)
			}
			u := got[0]
			if !strings.Contains(u.Where, tc.where) {
				t.Errorf("where = %q, want it to contain %q", u.Where, tc.where)
			}
			if !strings.Contains(u.Action, tc.action) {
				t.Errorf("action = %q, want it to contain %q", u.Action, tc.action)
			}
			for _, word := range []string{"ecosystem", "lang-pkgs", "os-pkgs"} {
				if strings.Contains(strings.ToLower(u.Where+u.Action), word) {
					t.Errorf("jargon %q leaked into %q / %q", word, u.Where, u.Action)
				}
			}
		})
	}
}

// The threshold follows configuration so the list matches whatever the policy
// calls urgent.
func TestUrgentHonoursConfiguredEPSS(t *testing.T) {
	v := sink.VulnView{ID: "CVE-1", EPSS: 0.6, FixAvailable: true}
	if got := urgent(urgentGroup(v).all(), 0); len(got) != 1 {
		t.Errorf("0.6 against the default 0.5 should be urgent")
	}
	if got := urgent(urgentGroup(v).all(), 0.7); len(got) != 0 {
		t.Errorf("0.6 against a configured 0.7 should not be urgent")
	}
}
