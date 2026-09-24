// Package kube implements a client-go LiveSource that reports the images
// actually running across one or more Kubernetes clusters. It is the real
// backing for live reconciliation: patchwright deploys to one cluster but can
// read many, using a kubeconfig with a read-only context per cluster.
//
// An image counts as running when a Running or Pending Pod uses it, or when a
// Deployment, StatefulSet, DaemonSet or unsuspended CronJob declares it. Pods alone
// are not enough: a CronJob has no pod between runs and a scaled-to-zero workload
// has none until it scales up, yet both are deployed and the image still needs
// fixing. Images left behind only by completed Jobs or deleted workloads are
// reported as not running, which removes a major source of scanner noise.
package kube

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
			// authMode=azure authenticates to AKS API servers with the identity this
			// process already has, so the kubeconfig needs to carry only each cluster's
			// URL and CA — nothing secret, and nothing to rotate.
			authMode: opts.String("authMode"),

			PublicHostnames:   splitCSV(opts.String("publicHostnames")),
			InternalHostnames: splitCSV(opts.String("internalHostnames")),
			InternalGateways:  splitCSV(opts.String("internalGateways")),
		}, nil
	})
}

type Source struct {
	kubeconfig string   // path to a kubeconfig; empty uses the default loading rules
	contexts   []string // context names to read; empty uses the current context
	inCluster  bool     // use the in-cluster service account instead of a kubeconfig
	// authMode replaces the kubeconfig's credentials: "azure" mints AAD tokens for AKS
	// from the ambient identity (workload identity, managed identity, az login). Empty
	// uses whatever the kubeconfig carries.
	authMode string

	// PublicHostnames and InternalHostnames name the DNS suffixes that do and do
	// not reach the internet. Most specific wins, so "example.com" can be public
	// while "pro.example.com" beneath it is not.
	//
	// This is the only thing in a cluster that can tell a route fronted by a public
	// load balancer from an identical one that is not: a gateway may have a proxy
	// in front of it that Kubernetes knows nothing about.
	PublicHostnames   []string
	InternalHostnames []string

	// InternalGateways names gateways that do not reach the internet, used only
	// when no public hostnames are configured. Coarser than hostnames and it
	// over-reports, which is the safe direction to be wrong in: it will not tell
	// somebody an internet-facing service is internal.
	InternalGateways []string

	// resolvers detect available upgrades per deployment system. Nil uses the
	// defaults (Flux HelmRelease); set for tests or to add resolvers.
	resolvers []UpgradeResolver
}

func (s *Source) Name() string { return "kube" }

// RunningImages returns a map of image NameTag -> running workload count across
// every configured cluster. It fails hard if any cluster's pods cannot be read, so
// liveness is never inferred from partial data.
func (s *Source) RunningImages(ctx context.Context) (map[string]int, error) {
	running, _, err := s.RunningImagesPartial(ctx)
	return running, err
}

// RunningImagesPartial is RunningImages that also reports whether any cluster
// refused a workload list. Pods are required; workload definitions are read where
// RBAC allows, because the grants for them reach clusters later than this code does,
// and refusing to reconcile at all would be worse than reconciling from pods alone.
func (s *Source) RunningImagesPartial(ctx context.Context) (map[string]int, bool, error) {
	clients, err := s.clients()
	if err != nil {
		return nil, false, err
	}
	running := map[string]int{}
	partial := false
	for label, client := range clients {
		p, err := collectRunningImages(ctx, label, client, running)
		if err != nil {
			return nil, false, fmt.Errorf("cluster %q: %w", label, err)
		}
		partial = partial || p
	}
	return running, partial, nil
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

func collectRunningImages(ctx context.Context, cluster string, client kubernetes.Interface, running map[string]int) (partial bool, err error) {
	pods, err := client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("list pods: %w", err)
	}
	count := func(spec corev1.PodSpec) {
		for _, c := range podContainers(spec) {
			running[model.ParseImageRef(c.Image).NameTag()]++
		}
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning && p.Status.Phase != corev1.PodPending {
			continue
		}
		count(p.Spec)
	}

	// A forbidden list is survivable; anything else is as fatal as the pod list,
	// since it says nothing about what RBAC allows and may hide a broken cluster.
	listFailed := func(resource string, err error) error {
		if !apierrors.IsForbidden(err) {
			return fmt.Errorf("list %s: %w", resource, err)
		}
		slog.WarnContext(ctx, "cannot read workload definitions for liveness; images deployed without a "+
			"running pod will not be seen, so nothing is judged not running this run",
			"cluster", cluster, "resource", resource, "missing_grant", "get,list on "+resource, "error", err)
		partial = true
		return nil
	}

	// Scaled-to-zero workloads count: they are still deployed (KEDA scales to zero)
	// and will run the image again as soon as they scale up.
	if deploys, err := client.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err != nil {
		if err := listFailed("deployments.apps", err); err != nil {
			return false, err
		}
	} else {
		for i := range deploys.Items {
			count(deploys.Items[i].Spec.Template.Spec)
		}
	}
	if sts, err := client.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err != nil {
		if err := listFailed("statefulsets.apps", err); err != nil {
			return false, err
		}
	} else {
		for i := range sts.Items {
			count(sts.Items[i].Spec.Template.Spec)
		}
	}
	if ds, err := client.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err != nil {
		if err := listFailed("daemonsets.apps", err); err != nil {
			return false, err
		}
	} else {
		for i := range ds.Items {
			count(ds.Items[i].Spec.Template.Spec)
		}
	}
	if cjs, err := client.BatchV1().CronJobs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err != nil {
		if err := listFailed("cronjobs.batch", err); err != nil {
			return false, err
		}
	} else {
		for i := range cjs.Items {
			cj := &cjs.Items[i]
			// A suspended CronJob has been switched off and schedules nothing.
			if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
				continue
			}
			count(cj.Spec.JobTemplate.Spec.Template.Spec)
		}
	}
	return partial, nil
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

	// One token source across every context: a single AAD token is valid for every
	// AAD-integrated cluster in the tenant, so a whole fleet costs one token.
	var tokens *azureTokenSource
	if strings.EqualFold(s.authMode, "azure") {
		t, err := newAzureTokenSource()
		if err != nil {
			return nil, err
		}
		tokens = t
	} else if s.authMode != "" {
		return nil, fmt.Errorf("unknown authMode %q (supported: azure)", s.authMode)
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
			if tokens != nil {
				tokens.apply(cfg)
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
