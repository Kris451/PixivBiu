package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
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

type tarEntry struct {
	mode int64
	data []byte
}

func makeTarGz(t *testing.T, files map[string]tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: f.mode, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(f.data); err != nil {
			t.Fatalf("write tar data: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// Extraction locates the binary structurally, not by a hardcoded filename: in a
// tar.gz it's the lone regular file with an execute bit (GoReleaser ships the
// binary 0755, docs 0644), so a binary rename can't break self-update.
func TestExtractBinaryTarGzPicksExecutable(t *testing.T) {
	bin := []byte("\x7fELF fake binary bytes")
	data := makeTarGz(t, map[string]tarEntry{
		"README.md": {mode: 0o644, data: []byte("# docs")},
		"PixivBiu":  {mode: 0o755, data: bin},
		"LICENSE":   {mode: 0o644, data: []byte("MIT")},
	})
	got, err := extractBinary("PixivBiu_3.1.0_linux_amd64.tar.gz", data, "PixivBiu")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if !bytes.Equal(got, bin) {
		t.Errorf("extracted %q, want the executable bytes %q", got, bin)
	}
}

func TestExtractBinaryTarGzNoExecutable(t *testing.T) {
	data := makeTarGz(t, map[string]tarEntry{
		"README.md": {mode: 0o644, data: []byte("# docs")},
		"LICENSE":   {mode: 0o644, data: []byte("MIT")},
	})
	if _, err := extractBinary("x_linux_amd64.tar.gz", data, "PixivBiu"); err == nil {
		t.Fatal("extractBinary on a docs-only archive = nil error; want an error")
	}
}

// In a Windows zip the binary is the sole .exe; docs never are. Match on the
// extension, not a literal name.
func TestExtractBinaryZipPicksExe(t *testing.T) {
	bin := []byte("MZ fake windows binary")
	data := makeZip(t, map[string][]byte{
		"README.md":    []byte("# docs"),
		"PixivBiu.exe": bin,
	})
	got, err := extractBinary("PixivBiu_3.1.0_windows_amd64.zip", data, "PixivBiu.exe")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if !bytes.Equal(got, bin) {
		t.Errorf("extracted %q, want the exe bytes %q", got, bin)
	}
}

func TestExtractBinaryZipNoExe(t *testing.T) {
	data := makeZip(t, map[string][]byte{
		"README.md": []byte("# docs"),
		"LICENSE":   []byte("MIT"),
	})
	if _, err := extractBinary("x_windows_amd64.zip", data, "PixivBiu.exe"); err == nil {
		t.Fatal("extractBinary on an exe-less zip = nil error; want an error")
	}
}

// With several executables bundled, the member named like the running binary
// (preferred) wins — not whichever happens to come first.
func TestExtractBinaryTarGzMultiplePrefersNamed(t *testing.T) {
	want := []byte("\x7fELF the real app binary")
	data := makeTarGz(t, map[string]tarEntry{
		"README.md":    {mode: 0o644, data: []byte("# docs")},
		"helper":       {mode: 0o755, data: []byte("\x7fELF a bundled helper")},
		"PixivBiu":     {mode: 0o755, data: want},
		"post-install": {mode: 0o755, data: []byte("#!/bin/sh\n")},
	})
	got, err := extractBinary("PixivBiu_3.1.0_linux_amd64.tar.gz", data, "PixivBiu")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("extracted %q, want the PixivBiu bytes %q", got, want)
	}
}

func TestExtractBinaryZipMultiplePrefersNamed(t *testing.T) {
	want := []byte("MZ the real app binary")
	data := makeZip(t, map[string][]byte{
		"README.md":    []byte("# docs"),
		"helper.exe":   []byte("MZ a bundled helper"),
		"PixivBiu.exe": want,
	})
	got, err := extractBinary("PixivBiu_3.1.0_windows_amd64.zip", data, "PixivBiu.exe")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("extracted %q, want the PixivBiu.exe bytes %q", got, want)
	}
}

// A binary renamed since the running build shipped: no member matches preferred,
// but there is exactly one executable, so the fallback installs it.
func TestExtractBinaryTarGzRenamedFallsBackToSole(t *testing.T) {
	want := []byte("\x7fELF renamed binary")
	data := makeTarGz(t, map[string]tarEntry{
		"README.md": {mode: 0o644, data: []byte("# docs")},
		"PixivPro":  {mode: 0o755, data: want},
	})
	got, err := extractBinary("PixivPro_4.0.0_linux_amd64.tar.gz", data, "PixivBiu")
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("extracted %q, want the sole executable %q", got, want)
	}
}

// Several executables and none named like us: refuse rather than guess.
func TestExtractBinaryTarGzAmbiguousErrors(t *testing.T) {
	data := makeTarGz(t, map[string]tarEntry{
		"alpha": {mode: 0o755, data: []byte("\x7fELF a")},
		"beta":  {mode: 0o755, data: []byte("\x7fELF b")},
	})
	if _, err := extractBinary("x_linux_amd64.tar.gz", data, "PixivBiu"); err == nil {
		t.Fatal("extractBinary on an ambiguous multi-executable archive = nil error; want an error")
	}
}

func TestExtractBinaryZipAmbiguousErrors(t *testing.T) {
	data := makeZip(t, map[string][]byte{
		"alpha.exe": []byte("MZ a"),
		"beta.exe":  []byte("MZ b"),
	})
	if _, err := extractBinary("x_windows_amd64.zip", data, "PixivBiu.exe"); err == nil {
		t.Fatal("extractBinary on an ambiguous multi-.exe archive = nil error; want an error")
	}
}
