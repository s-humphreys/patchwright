//go:build e2e

package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/s-humphreys/patchwright/pkg/config"
	"github.com/s-humphreys/patchwright/pkg/enrich"
	"github.com/s-humphreys/patchwright/pkg/enrich/kube"
	"github.com/s-humphreys/patchwright/pkg/model"
	"github.com/s-humphreys/patchwright/pkg/pipeline"
)

func kubeSource() enrich.LiveSource {
	src, err := enrich.NewLiveSource("kube", enrich.Options{"kubeconfig": kubeconfigPath})
	Expect(err).NotTo(HaveOccurred())
	return src
}

var _ = Describe("client-go live source", func() {
	It("reports running images and excludes completed jobs", func() {
		running, err := kubeSource().RunningImages(context.Background())
		Expect(err).NotTo(HaveOccurred())

		// The Deployment's image is running...
		Expect(running).To(HaveKey(model.ParseImageRef(runningImage).NameTag()),
			"expected the running Deployment image to be reported live")
		// ...but the Job has completed, so its image must not be counted.
		Expect(running).NotTo(HaveKey(model.ParseImageRef(completedImage).NameTag()),
			"expected the completed Job image to be absent from live images")
	})

	It("is registered under the expected name", func() {
		Expect(enrich.LiveSourceNames()).To(ContainElement("kube"))
		// Compile-time assertion that the concrete type satisfies the interface.
		var _ enrich.LiveSource = (*kube.Source)(nil)
	})
})

var _ = Describe("full pipeline with live reconciliation", func() {
	// occurrence builds a minimal critical occurrence for an image in a
	// namespace, enough for ownership + policy to consider it.
	occurrence := func(ref, namespace string) model.Occurrence {
		return model.Occurrence{
			Image: model.ParseImageRef(ref),
			Resource: model.Resource{
				Dimensions: map[string]string{"namespace": namespace, "account": "Production EU"},
			},
			Counts: model.Counts{model.SeverityCritical: 1},
		}
	}

	reconcilingConfig := func() *config.Config {
		return &config.Config{
			Owners: []config.OwnerRule{
				{Name: "eng", Match: "true", Class: "engineering", TeamFrom: "dimensions['namespace']"},
			},
			Actionable: []config.PolicyRule{
				{Name: "any-critical", When: "counts['critical'] > 0", Priority: "high"},
			},
			Suppress: []config.PolicyRule{
				{Name: "not-running", When: "reconciled && !live"},
			},
		}
	}

	It("keeps running findings actionable and suppresses not-running ones", func() {
		occ := []model.Occurrence{
			occurrence(runningImage, "app-a"),     // live
			occurrence(completedImage, "app-b"),   // job completed -> not live
			occurrence("acr.io/ghost:9", "app-c"), // never deployed -> not live
		}

		By("reconciling against the live cluster")
		Expect(enrich.NewLiveness(kubeSource()).Enrich(context.Background(), occ)).To(Succeed())

		pl, err := pipeline.New(reconcilingConfig())
		Expect(err).NotTo(HaveOccurred())
		findings, err := pl.Run(context.Background(), occ)
		Expect(err).NotTo(HaveOccurred())

		byImage := map[string]model.Finding{}
		for _, f := range findings {
			byImage[f.Image.NameTag()] = f
		}

		running := byImage[model.ParseImageRef(runningImage).NameTag()]
		Expect(running.Reconciled).To(BeTrue())
		Expect(running.Live).To(BeTrue())
		Expect(running.Actionable).To(BeTrue())
		Expect(running.Suppressed).To(BeFalse())

		completed := byImage[model.ParseImageRef(completedImage).NameTag()]
		Expect(completed.Live).To(BeFalse())
		Expect(completed.Suppressed).To(BeTrue(), "completed job image should be suppressed as not-running")
		Expect(completed.Actionable).To(BeFalse())

		ghost := byImage["acr.io/ghost:9"]
		Expect(ghost.Live).To(BeFalse())
		Expect(ghost.Suppressed).To(BeTrue(), "never-deployed image should be suppressed as not-running")
	})
})

var _ = Describe("namespace-label ownership", func() {
	It("attributes ownership from the team namespace label", func() {
		src := kubeSource()
		labeler := enrich.NewNamespaceLabeler(src.(enrich.LabelSource))

		occ := []model.Occurrence{{
			Image: model.ParseImageRef("acr.io/app:1"),
			Resource: model.Resource{
				Dimensions: map[string]string{"namespace": "e2e-team-a", "account": "Production EU"},
			},
			Counts: model.Counts{model.SeverityCritical: 1},
		}}

		By("enriching occurrences with namespace labels from the live cluster")
		Expect(labeler.Enrich(context.Background(), occ)).To(Succeed())
		Expect(occ[0].Resource.Labels).To(HaveKeyWithValue("team", "squad-alpha"))

		cfg := &config.Config{
			Owners: []config.OwnerRule{
				{Name: "by-label", Match: "'team' in labels", Class: "engineering", TeamFrom: "labels['team']"},
				{Name: "by-namespace", Match: "true", Class: "engineering", TeamFrom: "dimensions['namespace']"},
			},
			Actionable: []config.PolicyRule{
				{Name: "any-critical", When: "counts['critical'] > 0", Priority: "high"},
			},
		}
		pl, err := pipeline.New(cfg)
		Expect(err).NotTo(HaveOccurred())
		findings, err := pl.Run(context.Background(), occ)
		Expect(err).NotTo(HaveOccurred())

		Expect(findings).To(HaveLen(1))
		Expect(findings[0].Owner.Rule).To(Equal("by-label"), "the label rule should win over the namespace fallback")
		Expect(findings[0].Owner.Team).To(Equal("squad-alpha"))
	})
})
