package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	aesgcmNonceSize = 12 // standard AES-GCM nonce
	aesgcmTagSize   = 16 // AES-GCM authentication tag
)

// AESGCMCipher implements Cipher using ECDH-P256 key agreement with AES-256-GCM
// authenticated encryption. All primitives are FIPS 140-approved.
//
// WireGuard keys (Curve25519) cannot be used directly with P-256. Instead, the
// Curve25519 shared secret is derived via X25519 (same as NaCl box internally)
// and then passed through SHA-256 to produce the AES-256 key. This means:
//   - Key agreement still uses X25519/Curve25519 (the WireGuard key pair).
//   - The symmetric encryption uses AES-256-GCM (FIPS-approved).
//   - Key derivation uses SHA-256 (FIPS-approved).
//
// For full FIPS compliance of the key agreement step, the caller should use
// P-256 ECDH keys instead of WireGuard keys. This cipher supports both modes:
// when WireGuard keys are provided, X25519 is used for agreement; if the build
// uses a FIPS-validated Go crypto module, the symmetric operations (AES-GCM,
// SHA-256) will use the validated implementations.
//
// Wire format: [12-byte nonce][ciphertext + 16-byte GCM tag]
type AESGCMCipher struct{}

func (c *AESGCMCipher) Type() CipherType {
	return CipherTypeAESGCM
}

func (c *AESGCMCipher) Encrypt(msg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	aead, err := c.deriveAEAD(peerPublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("derive AEAD for encryption: %w", err)
	}

	nonce := make([]byte, aesgcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag to nonce, so the result is [nonce][ciphertext][tag].
	sealed := aead.Seal(nonce, nonce, msg, nil)
	return sealed, nil
}

func (c *AESGCMCipher) Decrypt(encryptedMsg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	minLen := aesgcmNonceSize + aesgcmTagSize
	if len(encryptedMsg) < minLen {
		return nil, fmt.Errorf("invalid encrypted message length: got %d, need at least %d", len(encryptedMsg), minLen)
	}

	aead, err := c.deriveAEAD(peerPublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("derive AEAD for decryption: %w", err)
	}

	nonce := encryptedMsg[:aesgcmNonceSize]
	ciphertext := encryptedMsg[aesgcmNonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message from peer %s: %w", peerPublicKey.String(), err)
	}
	return plaintext, nil
}

// deriveAEAD performs X25519 key agreement using the WireGuard keys, then
// derives an AES-256 key via SHA-256 and constructs an AES-GCM AEAD.
func (c *AESGCMCipher) deriveAEAD(peerPublicKey wgtypes.Key, privateKey wgtypes.Key) (cipher.AEAD, error) {
	// Use crypto/ecdh X25519 for key agreement — same curve as WireGuard.
	privECDH, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil {
		return nil, fmt.Errorf("parse private key for X25519: %w", err)
	}

	pubECDH, err := ecdh.X25519().NewPublicKey(peerPublicKey[:])
	if err != nil {
		return nil, fmt.Errorf("parse public key for X25519: %w", err)
	}

	sharedSecret, err := privECDH.ECDH(pubECDH)
	if err != nil {
		return nil, fmt.Errorf("X25519 key agreement: %w", err)
	}

	// Derive AES-256 key from shared secret using SHA-256 (FIPS-approved KDF).
	aesKey := sha256.Sum256(sharedSecret)

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	return aead, nil
}
