//go:build e2e

// Package e2e contains the kind-based integration suite. It is guarded by the
// "e2e" build tag so it is excluded from the normal `go test ./...` run and is
// executed only via `make test-integration` (which requires docker + kind).
//
// The suite stands up a real single-node Kubernetes cluster with kind, deploys
// a running Deployment and a completed Job, and exercises the client-go live
// source and the full pipeline against it — proving that reconciliation reports
// running images as live and completed/absent ones as not live.
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	clusterName = "patchwright-e2e"

	// Distinct images so "running" and "completed" are distinguishable by image.
	runningImage   = "busybox:1.36" // long-running Deployment
	completedImage = "alpine:3.20"  // one-shot Job that exits 0
)

var kubeconfigPath string

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "patchwright e2e suite")
}

var _ = BeforeSuite(func() {
	requireTools()

	f, err := os.CreateTemp("", "patchwright-e2e-kubeconfig-*")
	Expect(err).NotTo(HaveOccurred())
	kubeconfigPath = f.Name()
	Expect(f.Close()).To(Succeed())

	By("creating a kind cluster")
	runOK(300*time.Second, "kind", "create", "cluster",
		"--name", clusterName, "--kubeconfig", kubeconfigPath, "--wait", "120s")

	By("deploying a running workload and a completed job")
	applyManifests()

	By("waiting for the workloads to reach their expected states")
	runOK(180*time.Second, "kubectl", "--kubeconfig", kubeconfigPath,
		"wait", "--for=condition=available", "deployment/e2e-running", "--timeout=150s")
	runOK(180*time.Second, "kubectl", "--kubeconfig", kubeconfigPath,
		"wait", "--for=condition=complete", "job/e2e-completed", "--timeout=150s")
})

var _ = AfterSuite(func() {
	if kubeconfigPath == "" {
		return
	}
	By("deleting the kind cluster")
	_ = exec.Command("kind", "delete", "cluster", "--name", clusterName).Run()
	_ = os.Remove(kubeconfigPath)
})

// requireTools skips the whole suite when docker or kind is unavailable, so the
// suite is a no-op on machines that can't run it rather than a hard failure.
func requireTools() {
	if _, err := exec.LookPath("kind"); err != nil {
		Skip("kind not installed; run `make deps`")
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		Skip("kubectl not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		Skip("docker daemon not available; start Docker to run the integration suite")
	}
}

func applyManifests() {
	manifests := fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: e2e-team-a
  labels:
    team: squad-alpha
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: e2e-running
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels: { app: e2e-running }
  template:
    metadata:
      labels: { app: e2e-running }
    spec:
      containers:
        - name: main
          image: %s
          command: ["sleep", "3600"]
---
apiVersion: batch/v1
kind: Job
metadata:
  name: e2e-completed
  namespace: default
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: main
          image: %s
          command: ["true"]
`, runningImage, completedImage)

	cmd := exec.Command("kubectl", "--kubeconfig", kubeconfigPath, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifests)
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "kubectl apply failed: %s", out)
}

// runOK runs a command with a timeout and asserts it succeeds.
func runOK(timeout time.Duration, name string, args ...string) {
	GinkgoHelper()
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
		Expect(err).NotTo(HaveOccurred(), "%s %v failed: %s", name, args, out)
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		Fail(fmt.Sprintf("%s %v timed out after %s", name, args, timeout))
	}
}
