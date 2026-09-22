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
	d := newTemplateData(urgentGroup(
		sink.VulnView{ID: "CVE-HOT", EPSS: 0.9, FixAvailable: true},
		sink.VulnView{ID: "CVE-KEV", KEV: true, EPSS: 0.01, FixAvailable: true},
		sink.VulnView{ID: "CVE-NOFIX", KEV: true, FixAvailable: false},
		sink.VulnView{ID: "CVE-QUIET", EPSS: 0.2, FixAvailable: true},
	), nil, 0)
	if len(d.Urgent) != 2 {
		t.Fatalf("urgent = %+v, want CVE-KEV and CVE-HOT only", d.Urgent)
	}
	if d.Urgent[0].ID != "CVE-KEV" || d.Urgent[1].ID != "CVE-HOT" {
		t.Errorf("order = %s, %s; exploited in the wild must lead", d.Urgent[0].ID, d.Urgent[1].ID)
	}
	if d.Urgent[0].Why != "exploited in the wild" || d.Urgent[1].Why != "EPSS 0.90" {
		t.Errorf("why = %q, %q", d.Urgent[0].Why, d.Urgent[1].Why)
	}
}

// A ticket must not say "clears" unless the differential measured it, and must
// not say "does not clear" when nothing measured it either.
func TestUrgentTellsClearedFromUnmeasured(t *testing.T) {
	d := newTemplateData(urgentGroup(
		sink.VulnView{ID: "CVE-A", KEV: true, FixAvailable: true, Origin: "base", OriginDetermined: true, FixedByUpgrade: true},
		sink.VulnView{ID: "CVE-B", KEV: true, FixAvailable: true, Origin: "app", OriginDetermined: true},
		sink.VulnView{ID: "CVE-C", KEV: true, FixAvailable: true},
	), nil, 0)
	if d.UrgentCleared != 1 || d.UrgentUnknown != 1 || d.UrgentRemaining() != 1 {
		t.Errorf("cleared=%d unknown=%d remaining=%d, want 1/1/1", d.UrgentCleared, d.UrgentUnknown, d.UrgentRemaining())
	}
	if d.UrgentAllCleared() {
		t.Error("two of three not cleared, yet reported as all cleared")
	}
	byID := map[string]UrgentVuln{}
	for _, u := range d.Urgent {
		byID[u.ID] = u
	}
	if !strings.Contains(byID["CVE-A"].Action, "Nothing extra") {
		t.Errorf("cleared row should need nothing extra: %q", byID["CVE-A"].Action)
	}
	if !strings.Contains(byID["CVE-C"].Where, "Not determined") {
		t.Errorf("unmeasured row must say so, not blame the application: %q", byID["CVE-C"].Where)
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
	d := newTemplateData(g, nil, 0)
	if len(d.Urgent) != 1 || d.Urgent[0].Cleared {
		t.Errorf("one deployment keeps the CVE after the upgrade, yet it reads as cleared: %+v", d.Urgent)
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
			d := newTemplateData(urgentGroup(tc.v), nil, 0)
			if len(d.Urgent) != 1 {
				t.Fatalf("urgent = %+v", d.Urgent)
			}
			u := d.Urgent[0]
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
	if d := newTemplateData(urgentGroup(v), nil, 0); len(d.Urgent) != 1 {
		t.Errorf("0.6 against the default 0.5 should be urgent")
	}
	if d := newTemplateData(urgentGroup(v), nil, 0.7); len(d.Urgent) != 0 {
		t.Errorf("0.6 against a configured 0.7 should not be urgent")
	}
}
