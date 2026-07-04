package encryption

import (
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CipherType identifies the encryption algorithm used for message encryption.
type CipherType string

const (
	// CipherTypeNaCl uses Curve25519 + XSalsa20-Poly1305 (NaCl box). This is the
	// original NetBird encryption scheme. NOT FIPS-approved. Its wire format is
	// untagged and byte-compatible with upstream NetBird, so a client left on the
	// default cipher interoperates with a stock management/signal server.
	CipherTypeNaCl CipherType = "nacl"

	// CipherTypeAESGCM uses X25519 ECDH key agreement, a SHA-256 KDF, and
	// AES-256-GCM authenticated encryption.
	//
	// IMPORTANT: this is NOT end-to-end FIPS-approved. The AES-256-GCM and SHA-256
	// primitives are FIPS-approved, but X25519 key agreement is not on the
	// SP 800-56A approved-curve list. Full FIPS key agreement (P-256 ECDH with
	// dedicated keys) is deferred to the FIPS data-plane stage. Treat this cipher
	// as "AES-GCM control-plane encryption", not as a FIPS compliance claim.
	CipherTypeAESGCM CipherType = "aesgcm"
)

// cipherTagAESGCM is the 1-byte wire tag prepended by AESGCMCipher. It lets a
// misconfigured peer (one side nacl, the other aesgcm) fail loudly instead of
// producing an opaque AEAD error, and reserves room for future format
// revisions. NaCl intentionally carries no tag to stay wire-compatible with
// upstream NetBird.
const cipherTagAESGCM byte = 0x01

// Cipher provides authenticated encryption between two peers identified by
// WireGuard (Curve25519) key pairs.
//
// Implementations must be safe for concurrent use.
type Cipher interface {
	// Type returns the cipher identifier.
	Type() CipherType

	// Encrypt encrypts msg for the peer identified by peerPublicKey using our
	// privateKey. The returned ciphertext is self-contained (includes any nonce
	// or ephemeral key material needed for decryption).
	Encrypt(msg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error)

	// Decrypt decrypts a ciphertext produced by the remote peer's Encrypt call.
	// peerPublicKey is the remote peer's public key; privateKey is our private key.
	Decrypt(encryptedMsg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error)
}

var (
	activeCipher Cipher = &NaClCipher{} // default: backward compatible
	cipherMu     sync.RWMutex
)

// SetActiveCipher configures the cipher used by the package-level Encrypt and
// Decrypt functions. This should be called once at startup before any
// encryption operations. It is safe to call concurrently but switching ciphers
// while messages are in-flight will cause decryption failures.
func SetActiveCipher(c Cipher) {
	cipherMu.Lock()
	defer cipherMu.Unlock()
	activeCipher = c
}

// GetActiveCipher returns the currently active cipher.
func GetActiveCipher() Cipher {
	cipherMu.RLock()
	defer cipherMu.RUnlock()
	return activeCipher
}

// NewCipher creates a Cipher of the given type.
func NewCipher(ct CipherType) (Cipher, error) {
	switch ct {
	case CipherTypeNaCl:
		return &NaClCipher{}, nil
	case CipherTypeAESGCM:
		return &AESGCMCipher{}, nil
	default:
		return nil, fmt.Errorf("unsupported cipher type: %s", ct)
	}
}
