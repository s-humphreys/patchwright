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
	"github.com/s-humphreys/patchwright/pkg/model"

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

// kubectlOut runs kubectl and returns trimmed stdout.
func kubectlOut(args ...string) string {
	GinkgoHelper()
	out, err := exec.Command("kubectl", append([]string{"--kubeconfig", kubeconfigPath}, args...)...).Output()
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSpace(string(out))
}

func remediationKube() interface {
	enrich.UpgradeSource
	enrich.DeploymentContextSource
} {
	GinkgoHelper()
	src, err := enrich.NewLiveSource("kube", enrich.Options{"kubeconfig": kubeconfigPath})
	Expect(err).NotTo(HaveOccurred())
	s, ok := src.(interface {
		enrich.UpgradeSource
		enrich.DeploymentContextSource
	})
	Expect(ok).To(BeTrue(), "kube source should implement UpgradeSource + DeploymentContextSource")
	return s
}

var _ = Describe("remediation", Ordered, func() {
	BeforeAll(func() {
		By("installing Flux (source + helm controllers + CRDs)")
		runOK(300*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "apply", "-f", fluxInstallURL)
		runOK(120*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "wait", "--for=condition=established",
			"crd/helmreleases.helm.toolkit.fluxcd.io",
			"crd/helmrepositories.source.toolkit.fluxcd.io",
			"crd/kustomizations.kustomize.toolkit.fluxcd.io",
			"crd/gitrepositories.source.toolkit.fluxcd.io", "--timeout=90s")
		runOK(240*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "-n", "flux-system",
			"rollout", "status", "deployment/helm-controller", "deployment/source-controller", "--timeout=200s")

		By("deploying podinfo from an OCI Helm repository, pinned to an old chart version")
		kubectlApply(`
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata: { name: podinfo, namespace: flux-system }
spec:
  interval: 5m
  type: oci
  url: oci://ghcr.io/stefanprodan/charts
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
		By("waiting for the OCI HelmRelease to reconcile")
		runOK(300*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "-n", "flux-system",
			"wait", "--for=condition=Ready", "helmrelease/podinfo", "--timeout=240s")
	})

	It("detects a newer chart version from an OCI Helm repository", func() {
		upgrades, err := remediationKube().Upgrades(context.Background(), nil)
		Expect(err).NotTo(HaveOccurred())

		var found bool
		for _, up := range upgrades {
			if up.Name != "podinfo" {
				continue
			}
			found = true
			Expect(up.Kind).To(Equal("chart"))
			Expect(up.Current).To(Equal("6.5.0"))
			Expect(up.Available).To(BeTrue(), "6.5.0 should have a newer chart (latest %s)", up.Latest)
			Expect(up.Source).To(HavePrefix("oci://"), "source should be the OCI repository")
		}
		Expect(found).To(BeTrue(), "expected an OCI chart upgrade for podinfo, got %v", upgrades)
	})

	It("classifies operator-deployed images by whether the tag is set in the CR spec", func() {
		By("defining a custom resource that carries an image in its spec")
		kubectlApply(`
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: { name: apis.example.test }
spec:
  group: example.test
  scope: Namespaced
  names: { plural: apis, singular: api, kind: Api }
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
`)
		runOK(60*time.Second, "kubectl", "--kubeconfig", kubeconfigPath, "wait",
			"--for=condition=established", "crd/apis.example.test", "--timeout=30s")

		kubectlApply(`
apiVersion: example.test/v1
kind: Api
metadata: { name: my-api, namespace: default }
spec:
  image: nginx:1.27.0
`)
		uid := kubectlOut("get", "api", "my-api", "-n", "default", "-o", "jsonpath={.metadata.uid}")
		Expect(uid).NotTo(BeEmpty())

		By("deploying a workload owned by the CR: one container's image is in the spec, one is not")
		kubectlApply(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-workload
  namespace: default
  ownerReferences:
    - apiVersion: example.test/v1
      kind: Api
      name: my-api
      uid: ` + uid + `
      controller: true
spec:
  replicas: 0
  selector: { matchLabels: { app: api-workload } }
  template:
    metadata: { labels: { app: api-workload } }
    spec:
      containers:
        - { name: app, image: nginx:1.27.0 }
        - { name: side, image: redis:7.2.0 }
`)

		deployments, err := remediationKube().ImageDeployments(context.Background())
		Expect(err).NotTo(HaveOccurred())

		inSpec := deployments[model.ParseImageRef("nginx:1.27.0").NameTag()]
		Expect(inSpec.Mechanism).To(Equal("operator"))
		Expect(inSpec.Actionable).To(BeTrue(), "image set in the CR spec should be actionable")
		Expect(inSpec.Source).To(Equal("Api/default/my-api"))

		derived := deployments[model.ParseImageRef("redis:7.2.0").NameTag()]
		Expect(derived.Mechanism).To(Equal("operator"))
		Expect(derived.Actionable).To(BeFalse(), "image NOT in the CR spec should not be directly actionable")
	})

	It("resolves a Flux Kustomize source to its git repo and path, and detects label-based operators", func() {
		kubectlApply(`
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata: { name: infra, namespace: flux-system }
spec:
  interval: 5m
  url: https://github.com/acme/infra
  ref: { branch: main }
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata: { name: myapp, namespace: flux-system }
spec:
  interval: 5m
  path: ./apps/myapp
  prune: true
  sourceRef: { kind: GitRepository, name: infra }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kust-workload
  namespace: default
  labels:
    kustomize.toolkit.fluxcd.io/name: myapp
    kustomize.toolkit.fluxcd.io/namespace: flux-system
spec:
  replicas: 0
  selector: { matchLabels: { app: kust-workload } }
  template:
    metadata: { labels: { app: kust-workload } }
    spec:
      containers: [ { name: app, image: httpd:2.4.62 } ]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ctrl-workload
  namespace: default
  labels: { app.kubernetes.io/managed-by: flux-operator }
spec:
  replicas: 0
  selector: { matchLabels: { app: ctrl-workload } }
  template:
    metadata: { labels: { app: ctrl-workload } }
    spec:
      containers: [ { name: app, image: memcached:1.6.0 } ]
`)

		deployments, err := remediationKube().ImageDeployments(context.Background())
		Expect(err).NotTo(HaveOccurred())

		kust := deployments[model.ParseImageRef("httpd:2.4.62").NameTag()]
		Expect(kust.Mechanism).To(Equal("kustomize"))
		Expect(kust.Actionable).To(BeTrue())
		Expect(kust.Source).To(Equal("https://github.com/acme/infra//apps/myapp"))

		ctrl := deployments[model.ParseImageRef("memcached:1.6.0").NameTag()]
		Expect(ctrl.Mechanism).To(Equal("operator"), "app.kubernetes.io/managed-by should mark controller ownership")
		Expect(ctrl.Actionable).To(BeFalse())
	})
})
