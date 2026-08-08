package model

import "strings"

// defaultRegistry is used when an image reference omits an explicit registry
// host, matching Docker's convention.
const defaultRegistry = "docker.io"

// NameTag returns the "registry/repository:tag" form of an image, used to match
// scanner findings against live cluster state (which reports images the same
// way). The digest, if any, is omitted.
func (i Image) NameTag() string {
	name := i.Repository
	if i.Registry != "" {
		name = i.Registry + "/" + i.Repository
	}
	if i.Tag != "" {
		return name + ":" + i.Tag
	}
	return name
}

// ParseImageRef decomposes a container image reference into its registry,
// repository, tag and digest. It follows the usual Docker/OCI rules: the first
// path segment is treated as a registry only when it looks like a host (it
// contains "." or ":", or is "localhost"); otherwise the reference is assumed
// to be on Docker Hub. The original string is preserved in Ref.
//
//	registry.k8s.io/sig-storage/livenessprobe:v2.15.0
//	  -> {Registry: registry.k8s.io, Repository: sig-storage/livenessprobe, Tag: v2.15.0}
//	openpolicyagent/gatekeeper:v3.23.0
//	  -> {Registry: docker.io, Repository: openpolicyagent/gatekeeper, Tag: v3.23.0}
func ParseImageRef(ref string) Image {
	img := Image{Ref: ref}
	rem := ref

	// Split off an "@sha256:..." digest if present.
	if at := strings.LastIndex(rem, "@"); at != -1 {
		img.Digest = rem[at+1:]
		rem = rem[:at]
	}

	// Separate an explicit registry host from the repository path.
	name := rem
	if slash := strings.Index(rem, "/"); slash != -1 {
		first := rem[:slash]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			img.Registry = first
			name = rem[slash+1:]
		}
	}
	if img.Registry == "" {
		img.Registry = defaultRegistry
	}

	// A tag is a ":" in the final path segment (registry ports were already
	// separated above).
	tagStart := 0
	if lastSlash := strings.LastIndex(name, "/"); lastSlash != -1 {
		tagStart = lastSlash + 1
	}
	if colon := strings.LastIndex(name[tagStart:], ":"); colon != -1 {
		img.Repository = name[:tagStart+colon]
		img.Tag = name[tagStart+colon+1:]
	} else {
		img.Repository = name
	}
	return img
}
