package update

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/txperl/PixivBiu/internal/config"
)

func TestIsDevVersion(t *testing.T) {
	cases := map[string]bool{
		"0.1.0-dev":             true,  // the built-in default
		"":                      true,  // unset
		"v2.6.4b":               true,  // legacy, not valid semver
		"0.0.0-snapshot-abc123": true,  // goreleaser --snapshot
		"3.0.0-5-gdeadbee":      true,  // git describe between tags
		"3.0.0-dirty":           true,  // dirty worktree
		"3.0.0":                 false, // clean release
		"v3.0.0":                false, // clean release with v
		"3.1.0-beta.1":          false, // prerelease channel
		"3.1.0-rc.2":            false, // prerelease channel
		"v3.1.0-alpha":          false, // prerelease channel
	}
	for v, want := range cases {
		if got := isDevVersion(v); got != want {
			t.Errorf("isDevVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestDefaultChannel(t *testing.T) {
	cases := map[string]string{
		"3.1.0-alpha":    "alpha", // alpha build → alpha channel
		"v3.1.0-alpha.1": "alpha",
		"3.1.0-beta.1":   "beta", // beta build → beta channel
		"3.1.0-rc.2":     "beta", // rc folds into beta (no rc-only channel)
		"3.0.0":          "stable",
		"v3.0.0":         "stable",
		"0.1.0-dev":      "stable", // dev build stays on stable
		"":               "stable", // unset
		"v2.6.4b":        "stable", // legacy, not valid semver
	}
	for v, want := range cases {
		if got := DefaultChannel(v); got != want {
			t.Errorf("DefaultChannel(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestAssetName(t *testing.T) {
	// The version's leading "v" must be stripped to match GoReleaser's .Version.
	got := assetName("v3.0.0")
	if got == "" || got[:9] != "PixivBiu_" {
		t.Fatalf("assetName = %q, want PixivBiu_… prefix", got)
	}
}

// serveManifest serves the given manifest bytes at /manifest.json and the given
// detached signature at /manifest.json.minisig, returning the feed base URL.
func serveManifest(t *testing.T, data, sig []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Errorf("request missing User-Agent header")
		}
		switch r.URL.Path {
		case "/manifest.json":
			_, _ = w.Write(data)
		case "/manifest.json.minisig":
			_, _ = w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// signedFeed builds a manifest from releases, signs it with a fresh minisign key,
// serves it, and returns the feed base URL plus the trusted public key (base64).
func signedFeed(t *testing.T, releases []releaseEntry) (feedURL, pubKey string) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	data, err := json.Marshal(manifest{Schema: 1, Releases: releases})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return serveManifest(t, data, minisign.Sign(priv, data)), pub.String()
}

// newTestService wires a Service to a freshly-signed feed built from releases.
func newTestService(t *testing.T, current, channel string, releases []releaseEntry) *Service {
	t.Helper()
	feedURL, pubKey := signedFeed(t, releases)
	return NewService(current, feedURL, []string{pubKey}, config.UpdateConfig{
		Enabled: true,
		Channel: channel,
	}, "")
}

// withAssets attaches the archive for the running platform to r, so Check treats
// the release as installable here (mirrors a real release). The name is built
// from assetName so the fixture stays correct on whatever OS/arch the test runs
// on; the SHA-256 is a placeholder (Check only gates on the asset's presence).
func withAssets(r releaseEntry) releaseEntry {
	name := assetName(r.Tag)
	r.Assets = []asset{{Name: name, URL: "https://example/" + name, SHA256: "00"}}
	return r
}

func TestCheckUpdateAvailable(t *testing.T) {
	s := newTestService(t, "3.0.0", "stable", []releaseEntry{
		{Tag: "v3.0.0", HTMLURL: "https://example/v3.0.0"},
		withAssets(releaseEntry{Tag: "v3.1.0", HTMLURL: "https://example/v3.1.0"}),
		{Tag: "v2.6.4b"}, // legacy non-semver, must be ignored
	})
	st, err := s.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if st.LatestVersion != "v3.1.0" {
		t.Errorf("LatestVersion = %q, want v3.1.0", st.LatestVersion)
	}
	if !st.UpdateAvailable {
		t.Error("UpdateAvailable = false, want true")
	}
	if st.IsDev {
		t.Error("IsDev = true, want false for a clean release build")
	}
}

// TestCheckChannelFloors exercises the cumulative channel model: a channel
// accepts its own maturity floor and everything more stable. The fixture holds
// a stable, a beta, and an alpha; each channel should resolve to the newest tag
// it's allowed to see.
func TestCheckChannelFloors(t *testing.T) {
	// Filtering keys off the tag suffix (via releaseRank), not a prerelease bool.
	releases := []releaseEntry{
		withAssets(releaseEntry{Tag: "v3.0.0", HTMLURL: "https://example/v3.0.0"}),
		withAssets(releaseEntry{Tag: "v3.2.0-beta.1", HTMLURL: "https://example/beta"}),
		withAssets(releaseEntry{Tag: "v3.3.0-alpha.1", HTMLURL: "https://example/alpha"}),
	}

	cases := []struct {
		channel    string
		wantLatest string
		wantAvail  bool
	}{
		// Stable: betas/alphas invisible, so v3.0.0 is latest and we're current.
		{"stable", "v3.0.0", false},
		// Beta: accepts beta+stable but not alpha → the beta is newest.
		{"beta", "v3.2.0-beta.1", true},
		// Alpha: accepts everything → the alpha is newest.
		{"alpha", "v3.3.0-alpha.1", true},
		// Unknown channel falls back to the stable floor.
		{"nonsense", "v3.0.0", false},
	}
	for _, c := range cases {
		t.Run(c.channel, func(t *testing.T) {
			s := newTestService(t, "3.0.0", c.channel, releases)
			st, err := s.Check(context.Background())
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if st.LatestVersion != c.wantLatest {
				t.Errorf("LatestVersion = %q, want %q", st.LatestVersion, c.wantLatest)
			}
			if st.UpdateAvailable != c.wantAvail {
				t.Errorf("UpdateAvailable = %v, want %v", st.UpdateAvailable, c.wantAvail)
			}
		})
	}
}

func TestCheckDevBuildNeverOffersUpdate(t *testing.T) {
	s := newTestService(t, "0.1.0-dev", "stable", []releaseEntry{
		withAssets(releaseEntry{Tag: "v9.9.9", HTMLURL: "https://example/v9.9.9"}),
	})
	st, err := s.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !st.IsDev {
		t.Error("IsDev = false, want true for a dev build")
	}
	if st.UpdateAvailable {
		t.Error("UpdateAvailable = true, want false for a dev build")
	}
	// The latest version is still surfaced for display.
	if st.LatestVersion != "v9.9.9" {
		t.Errorf("LatestVersion = %q, want v9.9.9", st.LatestVersion)
	}
}

// A newer release is only advertised as available when it actually ships an
// installable archive for this platform; otherwise Apply would refuse it. The
// latest version is still surfaced for display, but without an offer or an asset
// name.
func TestCheckOnlyOffersApplicableReleases(t *testing.T) {
	const v = "v3.1.0"
	archive := asset{Name: assetName(v), URL: "https://example/a", SHA256: "00"}

	cases := map[string]struct {
		assets        []asset
		wantAvailable bool
	}{
		"archive for this platform": {[]asset{archive}, true},
		"no archive for any":        {nil, false},
		"archive for another OS": {[]asset{{
			Name: "PixivBiu_3.1.0_someos_somearch.tar.gz", URL: "https://example/x", SHA256: "00",
		}}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := newTestService(t, "3.0.0", "stable", []releaseEntry{
				{Tag: "v3.0.0"},
				{Tag: v, HTMLURL: "https://example/v3.1.0", Assets: c.assets},
			})
			st, err := s.Check(context.Background())
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if st.LatestVersion != v {
				t.Errorf("LatestVersion = %q, want %q (always surfaced)", st.LatestVersion, v)
			}
			if st.UpdateAvailable != c.wantAvailable {
				t.Errorf("UpdateAvailable = %v, want %v", st.UpdateAvailable, c.wantAvailable)
			}
			// AssetName tracks availability: set only when the offer is real.
			if (st.AssetName != "") != c.wantAvailable {
				t.Errorf("AssetName = %q, want non-empty=%v", st.AssetName, c.wantAvailable)
			}
		})
	}
}

// An update that skips intermediate versions should surface every skipped
// version's changelog, newest-first, each under its own "## <tag>" heading — not
// just the newest hop — with each body sanitized (commit SHA + "(@author)" + the
// per-release "## Changelog" heading stripped).
func TestCheckAggregatesNotesAcrossVersions(t *testing.T) {
	s := newTestService(t, "3.0.0", "stable", []releaseEntry{
		{Tag: "v3.1.0", Notes: "## Changelog\n### Features\n* 12d8eaacc0b65e76dede78bc67252c8f3be31827: feat: thing one (@txperl)"},
		{Tag: "v3.2.0", Notes: "## Changelog\n### Bug fixes\n* a6f4c52a5b4900fef85a47c7eaf523c758d0c4c3: fix: thing two (@txperl)"},
		withAssets(releaseEntry{Tag: "v3.3.0", HTMLURL: "https://example/v3.3.0", Notes: "## Changelog\n### Features\n* fbb56ddb997b8608aae3cd048f3ecae5b6543025: feat: thing three (@txperl)"}),
	})
	st, err := s.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	notes := st.ReleaseNotes
	for _, want := range []string{"## v3.3.0", "## v3.2.0", "## v3.1.0", "thing one", "thing two", "thing three"} {
		if !strings.Contains(notes, want) {
			t.Errorf("aggregated notes missing %q\n%s", want, notes)
		}
	}
	assertCleanedNotes(t, notes)
	// Newest-first ordering.
	i3, i2, i1 := strings.Index(notes, "## v3.3.0"), strings.Index(notes, "## v3.2.0"), strings.Index(notes, "## v3.1.0")
	if !(i3 < i2 && i2 < i1) {
		t.Errorf("versions not newest-first: v3.3.0@%d v3.2.0@%d v3.1.0@%d", i3, i2, i1)
	}
}

// A single-version jump carries no synthetic "## <tag>" heading, but the body is
// still sanitized for display (SHA + "(@author)" + "## Changelog" stripped).
func TestCheckSingleVersionNotesCleaned(t *testing.T) {
	s := newTestService(t, "3.0.0", "stable", []releaseEntry{
		{Tag: "v3.0.0"},
		withAssets(releaseEntry{Tag: "v3.1.0", HTMLURL: "https://example/v3.1.0", Notes: "## Changelog\n### Features\n* 12d8eaacc0b65e76dede78bc67252c8f3be31827: feat: only hop (@txperl)"}),
	})
	st, err := s.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	notes := st.ReleaseNotes
	if !strings.Contains(notes, "only hop") {
		t.Errorf("single-version notes lost the changelog text\n%s", notes)
	}
	if strings.Contains(notes, "## v3.1.0") {
		t.Errorf("single-version notes should not get a synthetic version heading\n%s", notes)
	}
	assertCleanedNotes(t, notes)
}

// assertCleanedNotes fails if display-ready notes still carry a commit SHA, an
// "(@author)" suffix, or a "## Changelog" heading.
func assertCleanedNotes(t *testing.T, notes string) {
	t.Helper()
	if strings.Contains(notes, "## Changelog") {
		t.Errorf("notes still contain a \"## Changelog\" heading\n%s", notes)
	}
	if strings.Contains(notes, "(@txperl)") {
		t.Errorf("notes still contain an \"(@author)\" suffix\n%s", notes)
	}
	if regexp.MustCompile(`[0-9a-f]{40}`).MatchString(notes) {
		t.Errorf("notes still contain a commit SHA\n%s", notes)
	}
}

func TestApplyRefusesDevBuild(t *testing.T) {
	s := NewService("0.1.0-dev", "https://dl.invalid", nil, config.UpdateConfig{}, "")
	err := s.Apply(context.Background())
	var ue *Error
	if !errors.As(err, &ue) || ue.Kind != KindRefused {
		t.Fatalf("Apply on a dev build = %v, want a KindRefused *Error", err)
	}
}

// A non-2xx from the feed must classify as upstream so the API returns 502, not a
// 400 with raw text.
func TestCheckClassifiesFeedFailureAsUpstream(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	s := NewService("3.0.0", ts.URL, []string{"unused"}, config.UpdateConfig{Enabled: true, Channel: "stable"}, "")
	_, err := s.Check(context.Background())
	var ue *Error
	if !errors.As(err, &ue) || ue.Kind != KindUpstream {
		t.Fatalf("Check against a failing feed = %v, want a KindUpstream *Error", err)
	}
}

// A manifest whose signature doesn't verify under the trusted key must be refused
// outright — an unverifiable feed is never parsed or trusted. This is the core
// guarantee of the minisign migration: tampering with the feed (even with valid
// JSON) cannot push an update.
func TestCheckRejectsInvalidSignature(t *testing.T) {
	// Sign with one key but trust a different one → verification must fail.
	_, signingPriv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	trustedPub, _, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate trusted key: %v", err)
	}
	data, err := json.Marshal(manifest{Schema: 1, Releases: []releaseEntry{
		withAssets(releaseEntry{Tag: "v3.1.0", HTMLURL: "https://example/v3.1.0"}),
	}})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	feedURL := serveManifest(t, data, minisign.Sign(signingPriv, data))

	s := NewService("3.0.0", feedURL, []string{trustedPub.String()}, config.UpdateConfig{Enabled: true, Channel: "stable"}, "")
	_, err = s.Check(context.Background())
	var ue *Error
	if !errors.As(err, &ue) || ue.Kind != KindRefused {
		t.Fatalf("Check with a bad signature = %v, want a KindRefused *Error", err)
	}
}

// No trusted key configured must also fail closed: without a key we cannot verify
// the feed, so no update is ever offered (the placeholder build state).
func TestCheckWithoutTrustedKeyIsRefused(t *testing.T) {
	feedURL, _ := signedFeed(t, []releaseEntry{
		withAssets(releaseEntry{Tag: "v3.1.0", HTMLURL: "https://example/v3.1.0"}),
	})
	s := NewService("3.0.0", feedURL, nil, config.UpdateConfig{Enabled: true, Channel: "stable"}, "")
	_, err := s.Check(context.Background())
	var ue *Error
	if !errors.As(err, &ue) || ue.Kind != KindRefused {
		t.Fatalf("Check with no trusted key = %v, want a KindRefused *Error", err)
	}
}

// "no applicable release" is a refusal (precondition), not a transport failure.
func TestCheckNoApplicableReleaseIsRefused(t *testing.T) {
	s := newTestService(t, "3.0.0", "stable", []releaseEntry{{Tag: "v2.6.4b"}}) // legacy non-semver only
	_, err := s.Check(context.Background())
	var ue *Error
	if !errors.As(err, &ue) || ue.Kind != KindRefused {
		t.Fatalf("Check with no semver release = %v, want a KindRefused *Error", err)
	}
}
