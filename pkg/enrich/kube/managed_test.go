package kube

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWorkloadMechanism(t *testing.T) {
	tests := []struct {
		name string
		meta metav1.ObjectMeta
		want string
	}{
		{
			name: "flux helm label",
			meta: metav1.ObjectMeta{Labels: map[string]string{"helm.toolkit.fluxcd.io/name": "app"}},
			want: "helm",
		},
		{
			name: "helm.sh chart label",
			meta: metav1.ObjectMeta{Labels: map[string]string{"helm.sh/chart": "app-1.2.3"}},
			want: "helm",
		},
		{
			name: "owned by a custom resource (operator)",
			meta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "tailscale.com/v1alpha1", Kind: "ProxyGroup"},
			}},
			want: "operator",
		},
		{
			name: "owned by a built-in kind is not operator-managed",
			meta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "Deployment"},
			}},
			want: "",
		},
		{
			name: "plain manifest / kustomize",
			meta: metav1.ObjectMeta{},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := workloadMechanism(tt.meta); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOwnerGroupIsCustom(t *testing.T) {
	cases := map[string]bool{
		"apps/v1":                   false,
		"batch/v1":                  false,
		"v1":                        false, // core
		"tailscale.com/v1alpha1":    true,
		"helm.toolkit.fluxcd.io/v2": true,
	}
	for apiVersion, want := range cases {
		if got := ownerGroupIsCustom(apiVersion); got != want {
			t.Errorf("ownerGroupIsCustom(%q) = %v, want %v", apiVersion, got, want)
		}
	}
}
