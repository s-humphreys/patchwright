# Build a static patchwright binary and ship it on a minimal distroless base.
# Cross-compiles for the target platform (set by buildx) from the native build
# platform, so multi-arch builds don't need QEMU emulation.
# Pinned to the patch release go.mod requires: see the toolchain directive there for
# the CVEs it carries fixes for. A floating tag would let a build pick a vulnerable
# toolchain without anything failing.
FROM --platform=$BUILDPLATFORM golang:1.26.6 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/patchwright ./cmd/patchwright

# Bundle the Trivy binary so in-cluster vulnerability scanning works out of the
# box (Trivy is a static binary and runs on distroless).
FROM aquasec/trivy:0.73.0 AS trivy

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/patchwright /usr/local/bin/patchwright
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/patchwright"]
