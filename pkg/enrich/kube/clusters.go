package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/s-humphreys/patchwright/internal/metrics"
	"github.com/s-humphreys/patchwright/pkg/model"
)

// defaultRetryAfter is the pause before the one retry of a failed cluster read. Long
// enough for a blip at an API server or its token webhook to pass, short enough that
// a cluster that is really down costs the assessment seconds rather than minutes.
const defaultRetryAfter = 2 * time.Second

// cluster is one configured cluster and the clients that read it.
type cluster struct {
	label string
	typed kubernetes.Interface
	dyn   dynamic.Interface
	// cfg backs discovery for custom resource lookups.
	cfg *rest.Config
}

// clusters builds the clients for every configured cluster, in label order so that
// "first cluster wins" merges are the same from one run to the next.
func (s *Source) clusters() ([]cluster, error) {
	if s.connect != nil {
		return s.connect()
	}
	configs, err := s.restConfigs()
	if err != nil {
		return nil, err
	}
	out := make([]cluster, 0, len(configs))
	for label, cfg := range configs {
		typed, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("build client for %q: %w", label, err)
		}
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("build dynamic client for %q: %w", label, err)
		}
		out = append(out, cluster{label: label, typed: typed, dyn: dyn, cfg: cfg})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].label < out[j].label })
	return out, nil
}

// readClusters runs read against each cluster in turn. A cluster whose read still
// fails after a retry (for the errors worth one) is left out and recorded, and the
// others carry on: one cluster returning 401 on one list call used to fail every
// assessment for the whole estate. Only when no cluster could be read does this
// fail, because then nothing was read at all.
//
// read must leave nothing behind from a failed attempt. Callers read into scratch
// state and keep it only when the whole cluster read, so a cluster is either in the
// result entirely or not at all.
func (s *Source) readClusters(ctx context.Context, stage string, clusters []cluster, read func(cluster) error) (dropped int, err error) {
	var errs []error
	for _, c := range clusters {
		err := s.readWithRetry(ctx, stage, c, read)
		if err == nil {
			continue
		}
		// A cancelled assessment is not a cluster fault, and recording it as one would
		// blame every remaining cluster for it.
		if ctx.Err() != nil {
			return dropped, fmt.Errorf("cluster %q: %w", c.label, err)
		}
		s.recordFailure(ctx, stage, c.label, err)
		errs = append(errs, fmt.Errorf("cluster %q: %w", c.label, err))
		dropped++
	}
	if len(clusters) > 0 && dropped == len(clusters) {
		return dropped, joinClusterErrors(errs)
	}
	return dropped, nil
}

func (s *Source) readWithRetry(ctx context.Context, stage string, c cluster, read func(cluster) error) error {
	err := read(c)
	if err == nil || !retryable(err) {
		return err
	}
	slog.InfoContext(ctx, "cluster read failed; retrying once", "cluster", c.label, "read", stage, "error", err)
	wait := s.retryAfter
	if wait <= 0 {
		wait = defaultRetryAfter
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return err
	case <-t.C:
	}
	return read(c)
}

// retryable reports whether a failed read is worth one more attempt. 401 is, because
// an AAD token can be rejected by one API server while still valid for the rest, and
// the Azure transport drops a rejected token so the retry presents a fresh one. So
// are the faults that pass on their own: 5xx, throttling, timeouts, dropped
// connections. 403 is not: RBAC does not change in two seconds.
func retryable(err error) bool {
	switch {
	case apierrors.IsForbidden(err):
		return false
	case apierrors.IsUnauthorized(err),
		apierrors.IsTooManyRequests(err),
		apierrors.IsServerTimeout(err),
		apierrors.IsTimeout(err),
		apierrors.IsInternalError(err),
		apierrors.IsServiceUnavailable(err),
		apierrors.IsUnexpectedServerError(err):
		return true
	}
	var status apierrors.APIStatus
	if errors.As(err, &status) {
		return status.Status().Code >= 500
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// IsProbableEOF compares the EOF sentinels only unwrapped or directly inside a
	// url.Error, and these errors arrive wrapped by the list that failed.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return utilnet.IsConnectionReset(err) || utilnet.IsConnectionRefused(err) || utilnet.IsProbableEOF(err)
}

func joinClusterErrors(errs []error) error {
	if len(errs) == 1 {
		return errs[0]
	}
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	return fmt.Errorf("no cluster could be read: %s", strings.Join(msgs, "; "))
}

func (s *Source) recordFailure(ctx context.Context, stage, label string, err error) {
	slog.WarnContext(ctx, "cluster could not be read; it is left out of this run rather than failing the assessment",
		"cluster", label, "read", stage, "error", err)
	metrics.ClusterReadFailure(label, stage)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, model.SourceFailure{Stage: stage, Cluster: label, Error: err.Error()})
}

// TakeClusterFailures implements enrich.ClusterFailureReporter.
func (s *Source) TakeClusterFailures() []model.SourceFailure {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.failures
	s.failures = nil
	return out
}
