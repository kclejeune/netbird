package encryption

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const naclNonceSize = 24

// NaClCipher implements Cipher using NaCl box (Curve25519 + XSalsa20-Poly1305).
// This is the original NetBird encryption scheme.
type NaClCipher struct{}

func (c *NaClCipher) Type() CipherType {
	return CipherTypeNaCl
}

func (c *NaClCipher) Encrypt(msg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	nonce, err := naclGenNonce()
	if err != nil {
		return nil, err
	}
	return box.Seal(nonce[:], msg, nonce, toByte32(peerPublicKey), toByte32(privateKey)), nil
}

func (c *NaClCipher) Decrypt(encryptedMsg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	if len(encryptedMsg) < naclNonceSize {
		return nil, fmt.Errorf("invalid encrypted message length")
	}
	var nonce [naclNonceSize]byte
	copy(nonce[:], encryptedMsg[:naclNonceSize])
	opened, ok := box.Open(nil, encryptedMsg[naclNonceSize:], &nonce, toByte32(peerPublicKey), toByte32(privateKey))
	if !ok {
		return nil, fmt.Errorf("failed to decrypt message from peer %s", peerPublicKey.String())
	}
	return opened, nil
}

func naclGenNonce() (*[naclNonceSize]byte, error) {
	var nonce [naclNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &nonce, nil
}
