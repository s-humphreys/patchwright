package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// fleet is a Source over fake clusters, retrying without the production pause.
func fleet(clients map[string]*kubefake.Clientset) *Source {
	return &Source{
		retryAfter: time.Millisecond,
		connect: func() ([]cluster, error) {
			var out []cluster
			for _, label := range []string{"a", "b", "c"} {
				if c, ok := clients[label]; ok {
					out = append(out, cluster{label: label, typed: c, dyn: fluxKustomizeDyn()})
				}
			}
			return out, nil
		},
	}
}

// failFirst makes a list fail with err the first n times, counting every call.
func failFirst(client *kubefake.Clientset, resource string, n int, err error) *int {
	calls := 0
	client.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls <= n {
			return true, nil, err
		}
		return false, nil, nil
	})
	return &calls
}

func unauthorized() error { return apierrors.NewUnauthorized("token rejected") }

func occurrence(image string) model.Occurrence {
	return model.Occurrence{Image: model.ParseImageRef(image)}
}

// The production failure: one remote cluster returned 401 on one list call, and every
// assessment for the whole estate failed with it.
func TestAClusterThatCannotBeReadIsLeftOutNotFatal(t *testing.T) {
	a := kubefake.NewSimpleClientset(runningPod("shared", "acr.io/shared:1"), runningPod("a", "acr.io/a-only:1"))
	b := kubefake.NewSimpleClientset(
		runningPod("shared", "acr.io/shared:1"),
		runningPod("b", "acr.io/b-only:1"),
		cronJob("job", "acr.io/b-job:1", nil),
	)
	calls := failFirst(b, "cronjobs", 2, unauthorized())
	src := fleet(map[string]*kubefake.Clientset{"a": a, "b": b})

	occ := []model.Occurrence{
		occurrence("acr.io/shared:1"), occurrence("acr.io/a-only:1"),
		occurrence("acr.io/b-only:1"), occurrence("acr.io/b-job:1"),
	}
	if err := enrich.NewLiveness(src).Enrich(context.Background(), occ); err != nil {
		t.Fatalf("one unreadable cluster must not fail the assessment: %v", err)
	}
	for _, o := range occ[:2] {
		if !o.Live || !o.Reconciled {
			t.Errorf("%s runs in the cluster that was read: live=%v reconciled=%v", o.Image.NameTag(), o.Live, o.Reconciled)
		}
	}
	// b's pods listed fine before its cronjobs failed, and still must not count: half
	// a cluster read as a whole one would call its CronJob images not running.
	for _, o := range occ[2:] {
		if o.Live || o.Reconciled {
			t.Errorf("%s is only in the unread cluster, so its liveness is unknown: live=%v reconciled=%v",
				o.Image.NameTag(), o.Live, o.Reconciled)
		}
	}
	if *calls != 2 {
		t.Errorf("cronjobs listed %d times, want one retry after the 401", *calls)
	}

	failures := src.TakeClusterFailures()
	if len(failures) != 1 {
		t.Fatalf("failures = %+v, want the one cluster", failures)
	}
	if f := failures[0]; f.Stage != model.StageLive || f.Cluster != "b" || f.Error == "" {
		t.Errorf("failure = %+v", f)
	}
	if again := src.TakeClusterFailures(); len(again) != 0 {
		t.Errorf("taken failures must not be reported again: %+v", again)
	}
}

func TestARetryThatSucceedsIsNotPartial(t *testing.T) {
	b := kubefake.NewSimpleClientset(cronJob("job", "acr.io/b-job:1", nil))
	calls := failFirst(b, "cronjobs", 1, unauthorized())
	src := fleet(map[string]*kubefake.Clientset{"a": kubefake.NewSimpleClientset(), "b": b})

	running, partial, err := src.RunningImagesPartial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if partial {
		t.Error("the retry read the cluster in full, so nothing is partial")
	}
	if running["acr.io/b-job:1"] != 1 {
		t.Errorf("the retried read should count once, not once per attempt: %v", running)
	}
	if *calls != 2 {
		t.Errorf("cronjobs listed %d times, want 2", *calls)
	}
	if f := src.TakeClusterFailures(); len(f) != 0 {
		t.Errorf("a cluster read on retry is not a failure: %+v", f)
	}
}

func TestEveryClusterFailingIsStillAFailedRead(t *testing.T) {
	a, b := kubefake.NewSimpleClientset(), kubefake.NewSimpleClientset()
	failFirst(a, "pods", 99, unauthorized())
	failFirst(b, "pods", 99, apierrors.NewServiceUnavailable("down"))
	src := fleet(map[string]*kubefake.Clientset{"a": a, "b": b})

	occ := []model.Occurrence{occurrence("acr.io/x:1")}
	if err := enrich.NewLiveness(src).Enrich(context.Background(), occ); err == nil {
		t.Fatal("nothing was read, so nothing was reconciled: the read must fail")
	}
}

func TestAPodListFailureDropsTheClusterNotTheAssessment(t *testing.T) {
	b := kubefake.NewSimpleClientset(runningPod("b", "acr.io/b:1"))
	calls := failFirst(b, "pods", 99, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("rbac")))
	src := fleet(map[string]*kubefake.Clientset{"a": kubefake.NewSimpleClientset(runningPod("a", "acr.io/a:1")), "b": b})

	running, partial, err := src.RunningImagesPartial(context.Background())
	if err != nil {
		t.Fatalf("pods are the floor of one cluster's liveness, not of the estate's: %v", err)
	}
	if !partial || running["acr.io/a:1"] == 0 || running["acr.io/b:1"] != 0 {
		t.Errorf("partial=%v running=%v", partial, running)
	}
	if *calls != 1 {
		t.Errorf("a 403 was retried (%d calls): RBAC does not change in two seconds", *calls)
	}
}

// Forbidden on a workload list degrades inside the cluster, as before: the cluster
// is still read, just without that list, and it is not a cluster failure.
func TestAForbiddenWorkloadListStillDegradesWithinTheCluster(t *testing.T) {
	b := kubefake.NewSimpleClientset(runningPod("b", "acr.io/b:1"), cronJob("job", "acr.io/b-job:1", nil))
	calls := failFirst(b, "cronjobs", 99, apierrors.NewForbidden(schema.GroupResource{Group: "batch", Resource: "cronjobs"}, "", errors.New("rbac")))
	src := fleet(map[string]*kubefake.Clientset{"a": kubefake.NewSimpleClientset(), "b": b})

	running, partial, err := src.RunningImagesPartial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !partial || running["acr.io/b:1"] == 0 || running["acr.io/b-job:1"] != 0 {
		t.Errorf("partial=%v running=%v", partial, running)
	}
	if *calls != 1 {
		t.Errorf("cronjobs listed %d times: a 403 is not retried", *calls)
	}
	if f := src.TakeClusterFailures(); len(f) != 0 {
		t.Errorf("a refused workload list is not an unreadable cluster: %+v", f)
	}
}

func TestACancelledReadIsNotBlamedOnTheCluster(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a := kubefake.NewSimpleClientset()
	a.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		cancel()
		return true, nil, context.Canceled
	})
	src := fleet(map[string]*kubefake.Clientset{"a": a, "b": kubefake.NewSimpleClientset()})

	if _, _, err := src.RunningImagesPartial(ctx); err == nil {
		t.Fatal("a cancelled assessment must stop, not carry on with the other clusters")
	}
	if f := src.TakeClusterFailures(); len(f) != 0 {
		t.Errorf("cancellation is not a cluster fault: %+v", f)
	}
}

func TestNamespaceLabelsLeaveOutAnUnreadableCluster(t *testing.T) {
	ns := func(name, team string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"team": team}}}
	}
	a := kubefake.NewSimpleClientset(ns("payments", "red"))
	b := kubefake.NewSimpleClientset(ns("search", "blue"))
	failFirst(b, "namespaces", 99, unauthorized())
	src := fleet(map[string]*kubefake.Clientset{"a": a, "b": b})

	labels, err := src.NamespaceLabels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if labels["payments"]["team"] != "red" || labels["search"] != nil {
		t.Errorf("labels = %v", labels)
	}
	if f := src.TakeClusterFailures(); len(f) != 1 || f[0].Stage != model.StageNamespaceLabels || f[0].Cluster != "b" {
		t.Errorf("failures = %+v", f)
	}

	failFirst(a, "namespaces", 99, unauthorized())
	if _, err := src.NamespaceLabels(context.Background()); err == nil {
		t.Error("no cluster's namespaces could be read, which must fail")
	}
}

func TestImageDeploymentsLeaveOutAnUnreadableCluster(t *testing.T) {
	a := kubefake.NewSimpleClientset(scaledDeployment("app", "acr.io/a:1", 1))
	b := kubefake.NewSimpleClientset(scaledDeployment("app", "acr.io/b:1", 1))
	failFirst(b, "statefulsets", 99, unauthorized())
	src := fleet(map[string]*kubefake.Clientset{"a": a, "b": b})

	contexts, err := src.ImageDeployments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := contexts["acr.io/a:1"]; !ok {
		t.Errorf("the readable cluster's contexts are kept: %v", contexts)
	}
	// Its deployments listed before its statefulsets failed: none of that is kept.
	if _, ok := contexts["acr.io/b:1"]; ok {
		t.Errorf("half of the unreadable cluster was kept: %v", contexts)
	}
	if f := src.TakeClusterFailures(); len(f) != 1 || f[0].Stage != model.StageDeployContext || f[0].Cluster != "b" {
		t.Errorf("failures = %+v", f)
	}
}

// clusterResolver reports an upgrade for its cluster's image, failing where told to.
type clusterResolver struct {
	images map[kubernetes.Interface]string
	fail   map[kubernetes.Interface]error
}

func (clusterResolver) Name() string { return "stub" }

func (r clusterResolver) Resolve(_ context.Context, typed kubernetes.Interface, _ dynamic.Interface) (map[string]model.Upgrade, error) {
	if err := r.fail[typed]; err != nil {
		return nil, err
	}
	return map[string]model.Upgrade{r.images[typed]: {Available: true}}, nil
}

func TestUpgradesLeaveOutAnUnreadableCluster(t *testing.T) {
	a, b := kubefake.NewSimpleClientset(), kubefake.NewSimpleClientset()
	src := fleet(map[string]*kubefake.Clientset{"a": a, "b": b})
	src.resolvers = []UpgradeResolver{clusterResolver{
		images: map[kubernetes.Interface]string{a: "acr.io/a:1", b: "acr.io/b:1"},
		fail:   map[kubernetes.Interface]error{b: fmt.Errorf("list deployments: %w", unauthorized())},
	}}

	ups, err := src.Upgrades(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ups["acr.io/a:1"]; !ok || len(ups) != 1 {
		t.Errorf("upgrades = %v", ups)
	}
	if f := src.TakeClusterFailures(); len(f) != 1 || f[0].Stage != model.StageClusterUpgrades || f[0].Cluster != "b" {
		t.Errorf("failures = %+v", f)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func TestRetryable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"unauthorized", unauthorized(), true},
		{"wrapped unauthorized", fmt.Errorf("list cronjobs.batch: %w", unauthorized()), true},
		{"service unavailable", apierrors.NewServiceUnavailable("down"), true},
		{"internal error", apierrors.NewInternalError(errors.New("boom")), true},
		{"throttled", apierrors.NewTooManyRequests("slow down", 1), true},
		{"server timeout", apierrors.NewServerTimeout(schema.GroupResource{Resource: "pods"}, "list", 1), true},
		{"bad gateway", apierrors.NewGenericServerResponse(502, "list", schema.GroupResource{}, "", "", 0, true), true},
		{"network timeout", fmt.Errorf("list pods: %w", timeoutErr{}), true},
		{"unexpected eof", fmt.Errorf("list pods: %w", io.ErrUnexpectedEOF), true},
		{"forbidden", apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("rbac")), false},
		{"not found", apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "x"), false},
		{"anything else", errors.New("no such host"), false},
	} {
		if got := retryable(tc.err); got != tc.want {
			t.Errorf("%s: retryable = %v, want %v", tc.name, got, tc.want)
		}
	}
}
