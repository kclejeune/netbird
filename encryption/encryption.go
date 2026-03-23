package encryption

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A set of tools to encrypt/decrypt messages being sent through the Signal Exchange Service or Management Service.
// By default, NaCl box (Curve25519 + XSalsa20-Poly1305) is used for backward compatibility.
// Call SetActiveCipher to switch to a FIPS-compliant cipher (AES-256-GCM).

// Encrypt encrypts a message using local Wireguard private key and remote peer's public key.
// It delegates to the currently active Cipher (see SetActiveCipher).
func Encrypt(msg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	return GetActiveCipher().Encrypt(msg, peerPublicKey, privateKey)
}

// Decrypt decrypts a message that has been encrypted by the remote peer using Wireguard private key and remote peer's public key.
// It delegates to the currently active Cipher (see SetActiveCipher).
func Decrypt(encryptedMsg []byte, peerPublicKey wgtypes.Key, privateKey wgtypes.Key) ([]byte, error) {
	return GetActiveCipher().Decrypt(encryptedMsg, peerPublicKey, privateKey)
}

// toByte32 converts a Wireguard key to byte array of size 32 (a format used by the golang crypto package).
func toByte32(key wgtypes.Key) *[32]byte {
	return (*[32]byte)(&key)
}
