package enrich

import (
	"context"
	"testing"

	"github.com/s-humphreys/patchwright/pkg/basescan"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func TestMatchFixToPackages(t *testing.T) {
	const ubuntuFix = "1.1.0-2ubuntu0.1"
	pkg := func(eco, name, fixedIn string) model.AffectedPackage {
		return model.AffectedPackage{Name: name, Ecosystem: eco, FixedIn: fixedIn}
	}
	tests := []struct {
		name      string
		fixed     string // the provider's per-CVE version
		packages  []model.AffectedPackage
		wantFix   bool
		wantFixed string
	}{
		{
			name:     "ubuntu package, ubuntu fix",
			fixed:    ubuntuFix,
			packages: []model.AffectedPackage{pkg("ubuntu", "libbrotli1", "")},
			wantFix:  true, wantFixed: ubuntuFix,
		},
		{
			name:     "ubuntu package, scanner agrees",
			fixed:    ubuntuFix,
			packages: []model.AffectedPackage{pkg("ubuntu", "libbrotli1", ubuntuFix)},
			wantFix:  true, wantFixed: ubuntuFix,
		},
		{
			name:  "azure linux package, ubuntu fix",
			fixed: ubuntuFix,
			packages: []model.AffectedPackage{
				pkg("azurelinux", "brotli", ""), pkg("azurelinux", "brotli-devel", ""),
			},
			wantFix: false,
		},
		{
			name:     "azure linux package, debian fix",
			fixed:    "3.11.2-6+deb12u9",
			packages: []model.AffectedPackage{pkg("azurelinux", "python3", "")},
			wantFix:  false,
		},
		{
			name:  "azure linux package, scanner's azure linux fix wins",
			fixed: ubuntuFix,
			packages: []model.AffectedPackage{
				pkg("azurelinux", "brotli", "1.1.0-3.azl3"), pkg("azurelinux", "brotli-devel", "1.1.0-3.azl3"),
			},
			wantFix: true, wantFixed: "1.1.0-3.azl3",
		},
		{
			name:     "scanner fix where the provider had none",
			packages: []model.AffectedPackage{pkg("azurelinux", "brotli", "1.1.0-3.azl3")},
			wantFix:  true, wantFixed: "1.1.0-3.azl3",
		},
		{
			name:     "azure linux package, its own marker",
			fixed:    "2.40.2-7.azl3",
			packages: []model.AffectedPackage{pkg("azurelinux", "util-linux", "")},
			wantFix:  true, wantFixed: "2.40.2-7.azl3",
		},
		{
			name:     "npm package, distro fix",
			fixed:    ubuntuFix,
			packages: []model.AffectedPackage{pkg("npm", "brotli", "")},
			wantFix:  false,
		},
		{
			name:     "nuget package, distro fix",
			fixed:    "2.9.14+dfsg-1.3ubuntu3.10",
			packages: []model.AffectedPackage{pkg("nuget", "System.Text.Json", "")},
			wantFix:  false,
		},
		{
			name:     "dotnet package, unmarked fix is not disproved",
			fixed:    "10.0.13, 11.0.0-rc.2, 8.0.5, 9.0.21",
			packages: []model.AffectedPackage{pkg("dotnet-core", "System.Security.Cryptography.Xml", "")},
			wantFix:  true, wantFixed: "10.0.13, 11.0.0-rc.2, 8.0.5, 9.0.21",
		},
		{
			name:  "one package the fix belongs to is enough",
			fixed: ubuntuFix,
			packages: []model.AffectedPackage{
				pkg("node-pkg", "nodejs", ""), pkg("ubuntu", "libbrotli1", ""),
			},
			wantFix: true, wantFixed: ubuntuFix,
		},
		{
			name:    "no packages named, provider's word stands",
			fixed:   ubuntuFix,
			wantFix: true, wantFixed: ubuntuFix,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := model.Vulnerability{ID: "CVE-1", FixAvailable: tc.fixed != "", FixedVersion: tc.fixed, Packages: tc.packages}
			matchFixToPackages(&v)
			if v.FixAvailable != tc.wantFix || v.FixedVersion != tc.wantFixed {
				t.Errorf("fix = %v %q, want %v %q", v.FixAvailable, v.FixedVersion, tc.wantFix, tc.wantFixed)
			}
		})
	}
}

// packageScanner reports fixed packages per reference, for the differential to
// name.
type packageScanner map[string]map[string][]basescan.Package

func (packageScanner) Name() string { return "packages" }

func (s packageScanner) ScanRef(_ context.Context, ref string) (*basescan.Result, error) {
	return &basescan.Result{Ref: ref, OSFamily: "azurelinux",
		Ecosystems: map[string]bool{"azurelinux": true}, CVEs: s[ref]}, nil
}

// The case seen live: an Azure Linux image whose base carries brotli, given an
// Ubuntu fix by the provider, was urgent under exploited-fixable-critical. After
// the differential names the package, the Ubuntu version no longer counts.
func TestBaseDiffDisownsAnotherDistrosFix(t *testing.T) {
	brotli := []basescan.Package{{Name: "brotli", Ecosystem: "azurelinux"}}
	s := packageScanner{
		"base@sha256:aaa": {"CVE-2026-111497": brotli},
		"base:new":        {"CVE-2026-111497": brotli},
	}
	e := &BaseDiffEnricher{Resolver: &basescan.Resolver{Scanner: s}}
	img := image("CVE-2026-111497")
	img.Vulns[0].Severity, img.Vulns[0].KEV = model.SeverityCritical, true
	img.Vulns[0].FixAvailable, img.Vulns[0].FixedVersion = true, "1.1.0-2ubuntu0.1"
	images := []model.AssessedImage{img}

	if err := e.EnrichImages(context.Background(), images); err != nil {
		t.Fatal(err)
	}
	if v := images[0].Vulns[0]; v.FixAvailable || v.FixedVersion != "" {
		t.Errorf("fix = %v %q, want none: an Ubuntu version cannot fix an Azure Linux package", v.FixAvailable, v.FixedVersion)
	}
}
