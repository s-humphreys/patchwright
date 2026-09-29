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
	"sync"
	"time"

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
		// Accepted and ignored rather than refused, so a deployment still passing them
		// keeps running; the warning is what tells somebody to take them out.
		for _, k := range []string{"publicHostnames", "internalHostnames", "internalGateways"} {
			if _, set := opts[k]; set {
				slog.Warn("live option ignored: internet exposure was removed", "option", k)
			}
		}
		return &Source{
			kubeconfig: opts.String("kubeconfig"),
			contexts:   splitCSV(opts.String("contexts")),
			inCluster:  opts.StringOr("inCluster", "false") == "true",
			// authMode=azure authenticates to AKS API servers with the identity this
			// process already has, so the kubeconfig needs to carry only each cluster's
			// URL and CA — nothing secret, and nothing to rotate.
			authMode: opts.String("authMode"),
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

	// resolvers detect available upgrades per deployment system. Nil uses the
	// defaults (Flux HelmRelease); set for tests or to add resolvers.
	resolvers []UpgradeResolver

	// connect replaces how clusters are reached. Nil builds them from the kubeconfig
	// or in-cluster config; set by tests.
	connect func() ([]cluster, error)
	// retryAfter is the pause before retrying a failed cluster read. Zero uses
	// defaultRetryAfter.
	retryAfter time.Duration

	// failures are the cluster reads left out since TakeClusterFailures last ran.
	mu       sync.Mutex
	failures []model.SourceFailure
}

func (s *Source) Name() string { return "kube" }

// RunningImages returns a map of image NameTag -> running workload count across
// every cluster that could be read. It does not say whether the read was partial;
// enrich.Liveness asks RunningImagesPartial, which does.
func (s *Source) RunningImages(ctx context.Context) (map[string]int, error) {
	running, _, err := s.RunningImagesPartial(ctx)
	return running, err
}

// RunningImagesPartial is RunningImages that also reports whether the read was
// partial: a cluster refused a workload list, or could not be read at all.
//
// Within a cluster, pods are required and workload definitions are read where RBAC
// allows, because the grants for them reach clusters later than this code does, and
// refusing to reconcile at all would be worse than reconciling from pods alone.
// Across clusters, one that cannot be read is left out whole (see readClusters), and
// the read fails only when none could be read.
func (s *Source) RunningImagesPartial(ctx context.Context) (map[string]int, bool, error) {
	clusters, err := s.clusters()
	if err != nil {
		return nil, false, err
	}
	running := map[string]int{}
	partial := false
	dropped, err := s.readClusters(ctx, model.StageLive, clusters, func(c cluster) error {
		seen := map[string]int{}
		p, err := collectRunningImages(ctx, c.label, c.typed, seen)
		if err != nil {
			return err
		}
		for image, n := range seen {
			running[image] += n
		}
		partial = partial || p
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return running, partial || dropped > 0, nil
}

// NamespaceLabels returns namespace name -> labels across every configured
// cluster, used to attribute ownership from labels such as "team". When a
// namespace name appears in more than one cluster, the first cluster's labels
// win (namespace names are assumed consistent across a fleet).
//
// A cluster whose namespaces cannot be read is left out: its namespaces carry no
// labels this run, so ownership falls back to the rules that do not need them.
func (s *Source) NamespaceLabels(ctx context.Context) (map[string]map[string]string, error) {
	clusters, err := s.clusters()
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	_, err = s.readClusters(ctx, model.StageNamespaceLabels, clusters, func(c cluster) error {
		nss, err := c.typed.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list namespaces: %w", err)
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
		return nil
	})
	if err != nil {
		return nil, err
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

	// A forbidden list is survivable; anything else fails this cluster's read like
	// the pod list, since it says nothing about what RBAC allows and may hide a
	// broken cluster. The caller then leaves the whole cluster out.
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

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
