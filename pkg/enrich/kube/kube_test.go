package kube

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/s-humphreys/patchwright/pkg/enrich"
)

func podSpec(image string) corev1.PodSpec {
	return corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}}
}

func runningPod(name, image string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec:       podSpec(image),
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func scaledDeployment(name, image string, replicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{Spec: podSpec(image)},
		},
	}
}

func cronJob(name, image string, suspend *bool) *batchv1.CronJob {
	return &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: batchv1.CronJobSpec{
			Schedule: "0 */2 * * *",
			Suspend:  suspend,
			JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
				Template: corev1.PodTemplateSpec{Spec: podSpec(image)},
			}},
		},
	}
}

func collect(t *testing.T, client *kubefake.Clientset) (map[string]int, bool) {
	t.Helper()
	running := map[string]int{}
	partial, err := collectRunningImages(context.Background(), "test", client, running)
	if err != nil {
		t.Fatal(err)
	}
	return running, partial
}

func refuse(client *kubefake.Clientset, resource string, err error) {
	client.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
}

func TestADeploymentScaledToZeroIsStillRunning(t *testing.T) {
	running, partial := collect(t, kubefake.NewSimpleClientset(scaledDeployment("keda", "acr.io/scaled:1", 0)))
	if running["acr.io/scaled:1"] == 0 {
		t.Errorf("a deployment at zero replicas is still deployed: %v", running)
	}
	if partial {
		t.Error("every list succeeded, so the read is complete")
	}
}

func TestStatefulSetsAndDaemonSetsCount(t *testing.T) {
	running, _ := collect(t, kubefake.NewSimpleClientset(
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "ns"},
			Spec:       appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{Spec: podSpec("acr.io/db:1")}},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "ns"},
			Spec:       appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: podSpec("acr.io/agent:1")}},
		},
	))
	for _, img := range []string{"acr.io/db:1", "acr.io/agent:1"} {
		if running[img] == 0 {
			t.Errorf("%s should count: %v", img, running)
		}
	}
}

// The production case: a CronJob running every two hours for twenty seconds has
// no pod almost all the time.
func TestACronJobBetweenRunsIsStillRunning(t *testing.T) {
	notSuspended := false
	running, _ := collect(t, kubefake.NewSimpleClientset(
		cronJob("snapshots", "acr.io/snapshots:1", nil),
		cronJob("explicit", "acr.io/explicit:1", &notSuspended),
	))
	for _, img := range []string{"acr.io/snapshots:1", "acr.io/explicit:1"} {
		if running[img] == 0 {
			t.Errorf("%s belongs to an active CronJob and should count: %v", img, running)
		}
	}
}

func TestASuspendedCronJobIsNotRunning(t *testing.T) {
	suspended := true
	running, _ := collect(t, kubefake.NewSimpleClientset(cronJob("off", "acr.io/off:1", &suspended)))
	if running["acr.io/off:1"] != 0 {
		t.Errorf("a suspended CronJob is switched off: %v", running)
	}
}

func TestInitContainersCount(t *testing.T) {
	dep := scaledDeployment("app", "acr.io/app:1", 1)
	dep.Spec.Template.Spec.InitContainers = []corev1.Container{{Name: "migrate", Image: "acr.io/migrate:1"}}
	pod := runningPod("p", "acr.io/pod:1")
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "acr.io/podinit:1"}}
	cj := cronJob("job", "acr.io/job:1", nil)
	cj.Spec.JobTemplate.Spec.Template.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "acr.io/jobinit:1"}}

	running, _ := collect(t, kubefake.NewSimpleClientset(dep, pod, cj))
	for _, img := range []string{"acr.io/migrate:1", "acr.io/podinit:1", "acr.io/jobinit:1"} {
		if running[img] == 0 {
			t.Errorf("init container image %s should count: %v", img, running)
		}
	}
}

func TestOnlyRunningAndPendingPodsCount(t *testing.T) {
	done := runningPod("done", "acr.io/done:1")
	done.Status.Phase = corev1.PodSucceeded
	pending := runningPod("pending", "acr.io/pending:1")
	pending.Status.Phase = corev1.PodPending

	running, _ := collect(t, kubefake.NewSimpleClientset(done, pending, runningPod("up", "acr.io/up:1")))
	if running["acr.io/done:1"] != 0 {
		t.Errorf("a completed pod is not running: %v", running)
	}
	if running["acr.io/pending:1"] == 0 || running["acr.io/up:1"] == 0 {
		t.Errorf("pending and running pods count: %v", running)
	}
}

// Remote clusters return 403 until the chart granting cronjobs rolls out: that
// must degrade liveness, not stop it.
func TestAForbiddenWorkloadListDegradesToAPartialRead(t *testing.T) {
	client := kubefake.NewSimpleClientset(
		runningPod("p", "acr.io/pod:1"),
		scaledDeployment("app", "acr.io/app:1", 0),
		cronJob("job", "acr.io/job:1", nil),
	)
	refuse(client, "cronjobs", apierrors.NewForbidden(schema.GroupResource{Group: "batch", Resource: "cronjobs"}, "", errors.New("rbac")))

	running, partial := collect(t, client)
	if running["acr.io/pod:1"] == 0 || running["acr.io/app:1"] == 0 {
		t.Errorf("what could be read should still count: %v", running)
	}
	if running["acr.io/job:1"] != 0 {
		t.Errorf("the refused CronJob list cannot have contributed: %v", running)
	}
	if !partial {
		t.Error("a refused workload list makes the read partial")
	}
}

func TestAForbiddenAppsListIsAlsoPartial(t *testing.T) {
	client := kubefake.NewSimpleClientset(runningPod("p", "acr.io/pod:1"), cronJob("job", "acr.io/job:1", nil))
	refuse(client, "deployments", apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "", errors.New("rbac")))

	running, partial := collect(t, client)
	if !partial {
		t.Error("a refused deployments list makes the read partial")
	}
	if running["acr.io/job:1"] == 0 || running["acr.io/pod:1"] == 0 {
		t.Errorf("the lists that were allowed should still count: %v", running)
	}
}

func TestAnyOtherWorkloadListErrorFails(t *testing.T) {
	client := kubefake.NewSimpleClientset()
	refuse(client, "cronjobs", apierrors.NewServiceUnavailable("down"))

	_, err := collectRunningImages(context.Background(), "test", client, map[string]int{})
	if err == nil {
		t.Fatal("an error other than forbidden says nothing about RBAC and must fail like the pod list")
	}
}

func TestAPodListErrorFailsEvenWhenForbidden(t *testing.T) {
	client := kubefake.NewSimpleClientset()
	refuse(client, "pods", apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("rbac")))

	if _, err := collectRunningImages(context.Background(), "test", client, map[string]int{}); err == nil {
		t.Fatal("pods are the floor of liveness; without them nothing can be said")
	}
}

// A deployment still passing the removed exposure options must keep starting.
func TestRemovedExposureOptionsAreAcceptedAndIgnored(t *testing.T) {
	src, err := enrich.NewLiveSource("kube", enrich.Options{
		"publicHostnames":   "example.com",
		"internalHostnames": "internal.example.com",
		"internalGateways":  "gateway-system/private",
	})
	if err != nil || src == nil {
		t.Fatalf("removed options must not refuse the source: %v", err)
	}
}
