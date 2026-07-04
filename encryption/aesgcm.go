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

// AESGCMCipher implements Cipher using X25519 ECDH key agreement, a SHA-256 KDF,
// and AES-256-GCM authenticated encryption, keyed from the peers' WireGuard
// (Curve25519) key pairs.
//
// FIPS status: NOT end-to-end FIPS-approved. AES-256-GCM and SHA-256 are
// FIPS-approved primitives, but X25519 key agreement is not on the SP 800-56A
// approved-curve list, so this cipher does not by itself satisfy FIPS 140. Full
// FIPS key agreement (P-256 ECDH with dedicated keys) is deferred to the FIPS
// data-plane stage. If the binary is built against a FIPS-validated Go crypto
// module the AES-GCM/SHA-256 operations will use the validated implementations,
// but the key-agreement step still would not qualify.
//
// The shared secret is derived once per message via X25519 and hashed with
// SHA-256 into the AES-256 key. This is static-static ECDH: the per-pair key is
// deterministic and long-lived (no forward secrecy). NIST caps random-96-bit
// nonce GCM at 2^32 messages per key; that is far beyond the control-plane
// message volume this cipher carries, but the ceiling is documented here for
// completeness.
//
// Wire format: [1-byte tag=cipherTagAESGCM][12-byte nonce][ciphertext + 16-byte GCM tag]
type AESGCMCipher struct{}

func (c *AESGCMCipher) Type() CipherType {
	return CipherTypeAESGCM
}

func (c *AESGCMCipher) Encrypt(msg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	aead, err := c.deriveAEAD(peerPublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("derive AEAD for encryption: %w", err)
	}

	// Prefix a 1-byte cipher tag so a nacl/aesgcm misconfiguration fails loudly
	// and future format revisions remain distinguishable. Layout:
	// [tag][nonce][ciphertext+GCM tag].
	out := make([]byte, 1+aesgcmNonceSize, 1+aesgcmNonceSize+len(msg)+aesgcmTagSize)
	out[0] = cipherTagAESGCM
	nonce := out[1 : 1+aesgcmNonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext+tag after the nonce, giving [tag][nonce][ct+tag].
	sealed := aead.Seal(out, nonce, msg, nil)
	return sealed, nil
}

func (c *AESGCMCipher) Decrypt(encryptedMsg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	minLen := 1 + aesgcmNonceSize + aesgcmTagSize
	if len(encryptedMsg) < minLen {
		return nil, fmt.Errorf("invalid encrypted message length: got %d, need at least %d", len(encryptedMsg), minLen)
	}

	if encryptedMsg[0] != cipherTagAESGCM {
		// Most likely a cipher mismatch (peer sent NaCl, or a future/unknown
		// AES-GCM format). Fail loudly rather than mangle the AEAD.
		return nil, fmt.Errorf("aesgcm: unexpected cipher tag 0x%02x (peer cipher mismatch?)", encryptedMsg[0])
	}

	aead, err := c.deriveAEAD(peerPublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("derive AEAD for decryption: %w", err)
	}

	nonce := encryptedMsg[1 : 1+aesgcmNonceSize]
	ciphertext := encryptedMsg[1+aesgcmNonceSize:]

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

	// Derive the AES-256 key by hashing the X25519 shared secret with SHA-256.
	// This is a single-purpose KDF (no salt/info); adequate for one fixed key per
	// peer pair. SHA-256 is FIPS-approved; the X25519 agreement that produced the
	// secret is not (see the type doc).
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
