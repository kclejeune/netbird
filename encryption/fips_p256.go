package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// This file provides a genuinely FIPS-approved authenticated-encryption envelope:
// ephemeral-static ECDH over NIST P-256 (SP 800-56A approved), an HKDF-SHA256
// key derivation, and AES-256-GCM. Unlike AESGCMCipher (which keys off the
// WireGuard Curve25519 identity via X25519 — not a FIPS-approved curve), every
// primitive here is on the FIPS-approved list, so when the binary is built
// against a FIPS-validated Go crypto module this envelope qualifies end to end.
//
// It does NOT plug into the WG-keyed Cipher interface: FIPS key agreement
// requires dedicated P-256 node identities rather than WireGuard keys. This is
// the building block; adopting it as the live control-plane envelope requires a
// P-256 identity/distribution layer (future work). It is directly usable now for
// FIPS-required point-to-point payloads (e.g. a roster sealed to a node).

const (
	p256HKDFInfo   = "tacmesh-fips-p256-aesgcm-v1"
	p256NonceSize  = 12
	p256TagSize    = 16
	p256PubkeySize = 65 // uncompressed P-256 point
)

// P256PrivateKey / P256PublicKey are dedicated FIPS identity keys (not WG keys).
type (
	P256PrivateKey = ecdh.PrivateKey
	P256PublicKey  = ecdh.PublicKey
)

// GenerateP256Key creates a fresh P-256 keypair for FIPS envelope use.
func GenerateP256Key() (*P256PrivateKey, *P256PublicKey, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

// SealP256 encrypts msg to recipientPub using ephemeral-static P-256 ECDH.
//
// Wire format: [65-byte ephemeral P-256 public key][12-byte nonce][ciphertext+tag].
func SealP256(msg []byte, recipientPub *P256PublicKey) ([]byte, error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	aead, err := aeadFromSecret(shared)
	if err != nil {
		return nil, err
	}

	ephPub := eph.PublicKey().Bytes() // 65 bytes uncompressed
	out := make([]byte, len(ephPub)+p256NonceSize, len(ephPub)+p256NonceSize+len(msg)+p256TagSize)
	copy(out, ephPub)
	nonce := out[len(ephPub) : len(ephPub)+p256NonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	// Bind the ephemeral public key as additional data so it can't be swapped.
	return aead.Seal(out, nonce, msg, ephPub), nil
}

// OpenP256 decrypts a SealP256 ciphertext with the recipient's private key.
func OpenP256(ciphertext []byte, recipientPriv *P256PrivateKey) ([]byte, error) {
	if len(ciphertext) < p256PubkeySize+p256NonceSize+p256TagSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	ephPubBytes := ciphertext[:p256PubkeySize]
	nonce := ciphertext[p256PubkeySize : p256PubkeySize+p256NonceSize]
	ct := ciphertext[p256PubkeySize+p256NonceSize:]

	ephPub, err := ecdh.P256().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral key: %w", err)
	}
	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	aead, err := aeadFromSecret(shared)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return pt, nil
}

// aeadFromSecret derives an AES-256-GCM AEAD from an ECDH shared secret via
// HKDF-SHA256 (all FIPS-approved).
func aeadFromSecret(shared []byte) (cipher.AEAD, error) {
	kdf := hkdf.New(sha256.New, shared, nil, []byte(p256HKDFInfo))
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	return cipher.NewGCM(block)
}
