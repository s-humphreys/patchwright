//go:build e2e

package e2e

import (
	"context"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/s-humphreys/patchwright/pkg/enrich"

	_ "github.com/s-humphreys/patchwright/pkg/enrich/kube"
)

const fluxInstallURL = "https://github.com/fluxcd/flux2/releases/latest/download/install.yaml"

// kubectlApply applies YAML from stdin against the e2e cluster.
func kubectlApply(yaml string) {
	GinkgoHelper()
	cmd := exec.Command("kubectl", "--kubeconfig", kubeconfigPath, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "kubectl apply failed: %s", out)
}

var _ = Describe("remediation — Flux Helm chart upgrades", Ordered, func() {
	BeforeAll(func() {
		By("installing Flux (source + helm controllers)")
		runOK(300*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "apply", "-f", fluxInstallURL)
		runOK(120*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "wait", "--for=condition=established",
			"crd/helmreleases.helm.toolkit.fluxcd.io", "crd/helmrepositories.source.toolkit.fluxcd.io", "--timeout=90s")
		runOK(240*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "-n", "flux-system",
			"rollout", "status", "deployment/helm-controller", "deployment/source-controller", "--timeout=200s")

		By("deploying podinfo via a HelmRelease pinned to an old chart version")
		kubectlApply(`
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata: { name: podinfo, namespace: flux-system }
spec:
  interval: 5m
  url: https://stefanprodan.github.io/podinfo
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata: { name: podinfo, namespace: flux-system }
spec:
  interval: 5m
  targetNamespace: podinfo
  install:
    createNamespace: true
  chart:
    spec:
      chart: podinfo
      version: 6.5.0
      sourceRef: { kind: HelmRepository, name: podinfo }
`)
		By("waiting for the HelmRelease to reconcile and deploy")
		runOK(300*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "-n", "flux-system",
			"wait", "--for=condition=Ready", "helmrelease/podinfo", "--timeout=240s")
		runOK(180*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "-n", "podinfo",
			"wait", "--for=condition=available", "deployment", "--all", "--timeout=150s")
	})

	It("reports a newer chart version for the Flux-deployed podinfo", func() {
		src, err := enrich.NewLiveSource("kube", enrich.Options{"kubeconfig": kubeconfigPath})
		Expect(err).NotTo(HaveOccurred())
		us, ok := src.(enrich.UpgradeSource)
		Expect(ok).To(BeTrue(), "kube source should implement UpgradeSource")

		upgrades, err := us.Upgrades(context.Background(), nil)
		Expect(err).NotTo(HaveOccurred())

		// The podinfo image (deployed from chart 6.5.0) should map to its
		// HelmRelease and report an available upgrade to a newer chart.
		var found bool
		for image, up := range upgrades {
			if up.Name == "podinfo" {
				found = true
				Expect(up.Kind).To(Equal("chart"))
				Expect(up.Current).To(Equal("6.5.0"))
				Expect(up.Available).To(BeTrue(), "6.5.0 should have a newer chart available (image %s, latest %s)", image, up.Latest)
				Expect(up.Latest).NotTo(BeEmpty())
			}
		}
		Expect(found).To(BeTrue(), "expected an upgrade entry for the podinfo chart, got %v", upgrades)
	})
})
