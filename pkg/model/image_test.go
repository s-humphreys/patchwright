package model

import "testing"

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want Image
	}{
		{
			name: "registry with dotted host and nested repo",
			ref:  "registry.k8s.io/sig-storage/livenessprobe:v2.15.0",
			want: Image{Registry: "registry.k8s.io", Repository: "sig-storage/livenessprobe", Tag: "v2.15.0", Ref: "registry.k8s.io/sig-storage/livenessprobe:v2.15.0"},
		},
		{
			name: "docker hub implied registry",
			ref:  "openpolicyagent/gatekeeper:v3.23.0",
			want: Image{Registry: "docker.io", Repository: "openpolicyagent/gatekeeper", Tag: "v3.23.0", Ref: "openpolicyagent/gatekeeper:v3.23.0"},
		},
		{
			name: "single-segment docker hub image",
			ref:  "nats:2.10.29",
			want: Image{Registry: "docker.io", Repository: "nats", Tag: "2.10.29", Ref: "nats:2.10.29"},
		},
		{
			name: "azure container registry",
			ref:  "acme.example.com/orders:1.0.381-rc",
			want: Image{Registry: "acme.example.com", Repository: "orders", Tag: "1.0.381-rc", Ref: "acme.example.com/orders:1.0.381-rc"},
		},
		{
			name: "deeply nested mcr path",
			ref:  "mcr.microsoft.com/oss/v2/kubernetes-csi/livenessprobe:v2.18.0",
			want: Image{Registry: "mcr.microsoft.com", Repository: "oss/v2/kubernetes-csi/livenessprobe", Tag: "v2.18.0", Ref: "mcr.microsoft.com/oss/v2/kubernetes-csi/livenessprobe:v2.18.0"},
		},
		{
			name: "registry with explicit port",
			ref:  "localhost:5000/team/app:dev",
			want: Image{Registry: "localhost:5000", Repository: "team/app", Tag: "dev", Ref: "localhost:5000/team/app:dev"},
		},
		{
			name: "no tag",
			ref:  "quay.io/argoproj/argo-events",
			want: Image{Registry: "quay.io", Repository: "argoproj/argo-events", Ref: "quay.io/argoproj/argo-events"},
		},
		{
			name: "digest pinned",
			ref:  "ghcr.io/fluxcd/source-controller@sha256:abc123",
			want: Image{Registry: "ghcr.io", Repository: "fluxcd/source-controller", Digest: "sha256:abc123", Ref: "ghcr.io/fluxcd/source-controller@sha256:abc123"},
		},
		{
			name: "tag and digest",
			ref:  "docker.io/library/nginx:1.27@sha256:def456",
			want: Image{Registry: "docker.io", Repository: "library/nginx", Tag: "1.27", Digest: "sha256:def456", Ref: "docker.io/library/nginx:1.27@sha256:def456"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseImageRef(tt.ref)
			if got != tt.want {
				t.Errorf("ParseImageRef(%q)\n got  %+v\n want %+v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestCountsNormalized(t *testing.T) {
	c := Counts{SeverityCritical: 3}
	n := c.Normalized()
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if _, ok := n[sev]; !ok {
			t.Errorf("Normalized() missing key %q", sev)
		}
	}
	if n[SeverityCritical] != 3 {
		t.Errorf("Normalized() dropped value: got %d, want 3", n[SeverityCritical])
	}
	if _, ok := c[SeverityHigh]; ok {
		t.Error("Normalized() mutated the receiver")
	}
}
