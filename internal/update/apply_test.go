package update

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/txperl/PixivBiu/internal/config"
)

// Apply is single-flight: a second call while one is already in progress is
// rejected as a conflict instead of racing two binary swaps on the same
// executable.
func TestApplyRejectsConcurrent(t *testing.T) {
	s := NewService("3.0.0", "https://dl.invalid", nil, config.UpdateConfig{}, "")
	s.applying.Store(true) // simulate an apply already running
	err := s.Apply(context.Background())
	var ue *Error
	if !errors.As(err, &ue) || ue.Kind != KindConflict {
		t.Fatalf("concurrent Apply = %v, want a KindConflict *Error", err)
	}
}

// Apply must refuse to install an archive whose SHA-256 doesn't match the value
// in the (verified) manifest — the download is authenticated by the signed
// manifest, so a mismatch means corruption or tampering. This drives the full
// path: fetch + verify manifest, resolve the asset, download it, compare hashes.
func TestApplyChecksumMismatch(t *testing.T) {
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	name := assetName("v3.1.0")
	const archivePath = "/dl/archive"

	var data, sig []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) })
	mux.HandleFunc("/manifest.json.minisig", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(sig) })
	mux.HandleFunc(archivePath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not a real archive")) // sha256 won't match the manifest's claim
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	data, err = json.Marshal(manifest{Schema: 1, Releases: []releaseEntry{{
		Tag: "v3.1.0",
		Assets: []asset{{
			Name:   name,
			URL:    srv.URL + archivePath,
			SHA256: strings.Repeat("0", 64), // valid-length hex, deliberately wrong
		}},
	}}})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	sig = minisign.Sign(priv, data)

	s := NewService("3.0.0", srv.URL, []string{pub.String()}, config.UpdateConfig{Enabled: true, Channel: "stable"}, "")
	err = s.Apply(context.Background())
	var ue *Error
	if !errors.As(err, &ue) || ue.Kind != KindRefused {
		t.Fatalf("Apply with a checksum mismatch = %v, want a KindRefused *Error", err)
	}
	if !strings.Contains(strings.ToLower(ue.Message), "checksum mismatch") {
		t.Errorf("message = %q, want it to mention a checksum mismatch", ue.Message)
	}
}

// readCapped must reject a stream larger than the cap rather than silently
// truncating it: the archive checksum doesn't cover the extracted binary, so a
// truncated member would otherwise be applied as a corrupt executable.
func TestReadCapped(t *testing.T) {
	// Larger than the cap → error, no partial data.
	if b, err := readCapped(bytes.NewReader(make([]byte, 11)), 10); err == nil {
		t.Errorf("readCapped(11, limit 10) = %d bytes, nil error; want oversize error", len(b))
	}
	// Exactly at the cap → returned whole (not truncated).
	if b, err := readCapped(bytes.NewReader(make([]byte, 10)), 10); err != nil || len(b) != 10 {
		t.Errorf("readCapped(10, limit 10) = (%d bytes, %v); want (10, nil)", len(b), err)
	}
	// Under the cap → returned verbatim.
	if b, err := readCapped(bytes.NewReader([]byte("hello")), 10); err != nil || string(b) != "hello" {
		t.Errorf("readCapped(5, limit 10) = (%q, %v); want (hello, nil)", b, err)
	}
}
