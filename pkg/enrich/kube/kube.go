// Package kube implements a client-go LiveSource that reports the images
// actually running across one or more Kubernetes clusters. It is the real
// backing for live reconciliation: patchwright deploys to one cluster but can
// read many, using a kubeconfig with a read-only context per cluster.
//
// Only Pods in the Running or Pending phase are counted, so images belonging to
// completed Jobs or scaled-to-zero workloads are correctly reported as not
// running — a major source of scanner noise.
package kube

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

func init() {
	enrich.Register("kube", func(opts enrich.Options) (enrich.LiveSource, error) {
		return &Source{
			kubeconfig: opts.String("kubeconfig"),
			contexts:   splitCSV(opts.String("contexts")),
			inCluster:  opts.StringOr("inCluster", "false") == "true",
		}, nil
	})
}

type Source struct {
	kubeconfig string   // path to a kubeconfig; empty uses the default loading rules
	contexts   []string // context names to read; empty uses the current context
	inCluster  bool     // use the in-cluster service account instead of a kubeconfig

	// resolvers detect available upgrades per deployment system. Nil uses the
	// defaults (Flux HelmRelease); set for tests or to add resolvers.
	resolvers []UpgradeResolver
}

func (s *Source) Name() string { return "kube" }

// RunningImages lists Running/Pending pods across every configured cluster and
// returns a map of image NameTag -> running workload count. It fails hard if
// any cluster cannot be read, so liveness is never inferred from partial data.
func (s *Source) RunningImages(ctx context.Context) (map[string]int, error) {
	clients, err := s.clients()
	if err != nil {
		return nil, err
	}
	running := map[string]int{}
	for label, client := range clients {
		if err := collectRunningImages(ctx, client, running); err != nil {
			return nil, fmt.Errorf("cluster %q: %w", label, err)
		}
	}
	return running, nil
}

// NamespaceLabels returns namespace name -> labels across every configured
// cluster, used to attribute ownership from labels such as "team". When a
// namespace name appears in more than one cluster, the first cluster's labels
// win (namespace names are assumed consistent across a fleet).
func (s *Source) NamespaceLabels(ctx context.Context) (map[string]map[string]string, error) {
	clients, err := s.clients()
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	for label, client := range clients {
		nss, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("cluster %q: list namespaces: %w", label, err)
		}
		for i := range nss.Items {
			ns := &nss.Items[i]
			existing := out[ns.Name]
			if existing == nil {
				existing = map[string]string{}
				out[ns.Name] = existing
			}
			for k, v := range ns.Labels {
				if _, ok := existing[k]; !ok {
					existing[k] = v
				}
			}
		}
	}
	return out, nil
}

func collectRunningImages(ctx context.Context, client kubernetes.Interface, running map[string]int) error {
	pods, err := client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodPending {
			continue
		}
		for _, c := range p.Spec.InitContainers {
			running[model.ParseImageRef(c.Image).NameTag()]++
		}
		for _, c := range p.Spec.Containers {
			running[model.ParseImageRef(c.Image).NameTag()]++
		}
	}
	return nil
}

// restConfigs builds a *rest.Config per configured cluster, keyed by a label
// for error messages. It supports reading the local cluster via the in-cluster
// service account and/or remote clusters via kubeconfig contexts, so a single
// deployment can reconcile the cluster it runs in (RBAC only, no credentials)
// alongside remote clusters (read-only kubeconfig).
func (s *Source) restConfigs() (map[string]*rest.Config, error) {
	out := map[string]*rest.Config{}

	if s.inCluster {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("in-cluster config: %w", err)
		}
		out["in-cluster"] = cfg
	}

	// Load kubeconfig contexts when explicitly requested, or as the default
	// when in-cluster reading was not requested (local development).
	if len(s.contexts) > 0 || s.kubeconfig != "" || !s.inCluster {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		if s.kubeconfig != "" {
			loadingRules.ExplicitPath = s.kubeconfig
		}
		contexts := s.contexts
		if len(contexts) == 0 {
			contexts = []string{""} // "" means the kubeconfig's current context
		}
		for _, ctxName := range contexts {
			cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
				loadingRules,
				&clientcmd.ConfigOverrides{CurrentContext: ctxName},
			).ClientConfig()
			if err != nil {
				return nil, fmt.Errorf("build config for context %q: %w", ctxName, err)
			}
			label := ctxName
			if label == "" {
				label = "current-context"
			}
			out[label] = cfg
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no clusters configured")
	}
	return out, nil
}

// clients builds a typed Kubernetes client per configured cluster.
func (s *Source) clients() (map[string]kubernetes.Interface, error) {
	configs, err := s.restConfigs()
	if err != nil {
		return nil, err
	}
	out := make(map[string]kubernetes.Interface, len(configs))
	for label, cfg := range configs {
		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("build client for %q: %w", label, err)
		}
		out[label] = cs
	}
	return out, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
