package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"aead.dev/minisign"
)

// manifest is the signed release feed served from the update CDN, replacing the
// GitHub Releases API as the source of truth for "what releases exist". CI
// regenerates and re-signs it on every release; releases are ordered newest
// first. The client verifies its minisign signature before trusting any field.
type manifest struct {
	Schema      int            `json:"schema"`
	GeneratedAt time.Time      `json:"generated_at"`
	Releases    []releaseEntry `json:"releases"`
}

// releaseEntry is one release in the feed. Notes is the raw GoReleaser-style
// changelog body (sanitized for display by sanitizeReleaseBody, exactly as the
// former GitHub release body was), HTMLURL points at the human-readable release
// page (the GitHub release, still published as a mirror), and Assets carries the
// per-platform archives with their sizes and SHA-256 checksums inline — so the
// signed manifest is the single source for both discovery and verification.
type releaseEntry struct {
	Tag         string    `json:"tag"`     // e.g. v3.1.0
	Version     string    `json:"version"` // e.g. 3.1.0 (GoReleaser's .Version; informational)
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Notes       string    `json:"notes"`
	Assets      []asset   `json:"assets"`
}

// asset is one downloadable archive for a specific OS/arch. URL is absolute
// (built by CI against the CDN base); SHA256 is lowercase hex and is what Apply
// verifies the download against.
type asset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Read caps for the feed objects: the manifest is tens of KB and a minisign
// signature a few hundred bytes; these bound a runaway/oversized response.
const (
	maxManifest  = 4 << 20 // 4 MiB
	maxSignature = 8 << 10 // 8 KiB
)

// fetchManifest downloads the feed and its detached signature (the `.minisig`
// alongside manifest.json), verifies the signature against the trusted keys, and
// returns the releases (newest first). A transport/HTTP failure is upstream; a
// signature failure is a refusal — an unverifiable feed is never trusted — while
// a validly-signed manifest that fails to decode is an origin/CI defect, so it is
// upstream. The list also bounds how far back aggregateNotes can stitch
// changelogs for a multi-version jump (CI keeps the most recent ~20, covering any
// realistic gap between checks for this cadence).
func (s *Service) fetchManifest(ctx context.Context) ([]releaseEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	base := strings.TrimRight(s.feedURL, "/")
	data, err := s.fetchBytes(ctx, base+"/manifest.json", maxManifest)
	if err != nil {
		return nil, err
	}
	sig, err := s.fetchBytes(ctx, base+"/manifest.json.minisig", maxSignature)
	if err != nil {
		return nil, err
	}
	if err := s.verifyManifest(data, sig); err != nil {
		return nil, err
	}

	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, upstreamErr(fmt.Errorf("decode manifest: %w", err))
	}
	return m.Releases, nil
}

// parsePublicKeys parses minisign public-key strings (base64, the line after the
// untrusted-comment line) into keys, silently dropping any that don't parse — a
// build-time typo in a baked-in key then just leaves the updater fail-closed
// rather than panicking. Called once from NewService.
func parsePublicKeys(keys []string) []minisign.PublicKey {
	out := make([]minisign.PublicKey, 0, len(keys))
	for _, ks := range keys {
		var pk minisign.PublicKey
		if err := pk.UnmarshalText([]byte(ks)); err == nil {
			out = append(out, pk)
		}
	}
	return out
}

// verifyManifest returns nil iff sig is a valid minisign signature of data under
// one of the trusted keys (parsed once at construction). With no usable key it
// fails closed — an unverifiable feed must never be trusted, even by accident.
// minisign.Verify accepts both plain and prehashed (HashEdDSA) signatures, so a
// signature produced by the minisign CLI in CI verifies here unchanged.
func (s *Service) verifyManifest(data, sig []byte) error {
	if len(s.trustedKeys) == 0 {
		return refusedf("no trusted update key is configured; refusing to trust the update feed")
	}
	for _, pk := range s.trustedKeys {
		if minisign.Verify(pk, data, sig) {
			return nil
		}
	}
	return refusedf("update manifest signature is invalid; refusing to trust the update feed")
}

// fetchBytes GETs url under the caller's context, rejecting a non-200 or a body
// larger than limit. Transport/HTTP failures are categorized as upstream.
func (s *Service) fetchBytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, internalErr("could not build update request", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, upstreamErr(fmt.Errorf("fetch %s: %w", url, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil, upstreamErr(fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, upstreamErr(fmt.Errorf("read %s: %w", url, err))
	}
	return body, nil
}
