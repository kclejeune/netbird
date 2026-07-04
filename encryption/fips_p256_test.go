package encryption_test

import (
	"bytes"
	"testing"

	"github.com/netbirdio/netbird/encryption"
)

func TestP256_SealOpenRoundTrip(t *testing.T) {
	rpriv, rpub, err := encryption.GenerateP256Key()
	if err != nil {
		t.Fatalf("GenerateP256Key: %v", err)
	}

	for _, msg := range [][]byte{[]byte("hello fips"), {}, bytes.Repeat([]byte{0xAB}, 4096)} {
		ct, err := encryption.SealP256(msg, rpub)
		if err != nil {
			t.Fatalf("SealP256: %v", err)
		}
		pt, err := encryption.OpenP256(ct, rpriv)
		if err != nil {
			t.Fatalf("OpenP256: %v", err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("round-trip mismatch: got %q want %q", pt, msg)
		}
	}
}

func TestP256_WrongRecipientFails(t *testing.T) {
	_, rpub, _ := encryption.GenerateP256Key()
	otherPriv, _, _ := encryption.GenerateP256Key()

	ct, err := encryption.SealP256([]byte("secret"), rpub)
	if err != nil {
		t.Fatalf("SealP256: %v", err)
	}
	if _, err := encryption.OpenP256(ct, otherPriv); err == nil {
		t.Fatal("expected decryption to fail with the wrong recipient key")
	}
}

func TestP256_TamperFails(t *testing.T) {
	rpriv, rpub, _ := encryption.GenerateP256Key()
	ct, err := encryption.SealP256([]byte("integrity"), rpub)
	if err != nil {
		t.Fatalf("SealP256: %v", err)
	}
	// Flip a byte in the AEAD body (after the 65-byte ephemeral key + 12 nonce).
	ct[len(ct)-1] ^= 0xFF
	if _, err := encryption.OpenP256(ct, rpriv); err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext")
	}
}

func TestP256_SwapEphemeralKeyFails(t *testing.T) {
	rpriv, rpub, _ := encryption.GenerateP256Key()
	ct, err := encryption.SealP256([]byte("bind-check"), rpub)
	if err != nil {
		t.Fatalf("SealP256: %v", err)
	}
	// Corrupt a byte inside the ephemeral public key region (bound as AAD).
	ct[5] ^= 0xFF
	if _, err := encryption.OpenP256(ct, rpriv); err == nil {
		t.Fatal("expected failure when the bound ephemeral key is altered")
	}
}

func TestP256_UniqueCiphertexts(t *testing.T) {
	rpriv, rpub, _ := encryption.GenerateP256Key()
	a, _ := encryption.SealP256([]byte("same"), rpub)
	b, _ := encryption.SealP256([]byte("same"), rpub)
	if bytes.Equal(a, b) {
		t.Fatal("each Seal must use a fresh ephemeral key + nonce (distinct ciphertexts)")
	}
	// Both still decrypt.
	if pt, err := encryption.OpenP256(a, rpriv); err != nil || string(pt) != "same" {
		t.Fatalf("decrypt a: %v %q", err, pt)
	}
	if pt, err := encryption.OpenP256(b, rpriv); err != nil || string(pt) != "same" {
		t.Fatalf("decrypt b: %v %q", err, pt)
	}
}

func TestP256_ShortCiphertext(t *testing.T) {
	rpriv, _, _ := encryption.GenerateP256Key()
	if _, err := encryption.OpenP256([]byte{1, 2, 3}, rpriv); err == nil {
		t.Fatal("expected error on too-short ciphertext")
	}
}
