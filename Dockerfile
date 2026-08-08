# Build a static patchwright binary and ship it on a minimal distroless base.
# Cross-compiles for the target platform (set by buildx) from the native build
# platform, so multi-arch builds don't need QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/patchwright ./cmd/patchwright

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/patchwright /usr/local/bin/patchwright
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/patchwright"]
