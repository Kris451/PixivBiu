package main

import (
	"testing"

	"aead.dev/minisign"
)

// TestUpdateTrustedKeysParse guards the baked-in update-signing public keys. A
// typo'd key is silently dropped at runtime (update.parsePublicKeys), which would
// leave the updater fail-closed — no update ever offered — with no obvious signal.
// Catch it here. updateFeedURL must also be set, or checks fail closed too.
func TestUpdateTrustedKeysParse(t *testing.T) {
	if updateFeedURL == "" || len(updateTrustedKeys) == 0 {
		t.Fatal("updateFeedURL / updateTrustedKeys are unset; self-update is disabled (fails closed)")
	}
	for _, k := range updateTrustedKeys {
		var pk minisign.PublicKey
		if err := pk.UnmarshalText([]byte(k)); err != nil {
			t.Errorf("updateTrustedKeys entry %q is not a valid minisign public key: %v", k, err)
		}
	}
}
