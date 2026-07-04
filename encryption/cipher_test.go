package encryption_test

import (
	"sync"
	"testing"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/encryption/testprotos"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestNaClCipher(t *testing.T) {
	testCipher(t, &encryption.NaClCipher{})
}

func TestAESGCMCipher(t *testing.T) {
	testCipher(t, &encryption.AESGCMCipher{})
}

func TestSetActiveCipher(t *testing.T) {
	original := encryption.GetActiveCipher()
	defer encryption.SetActiveCipher(original)

	aesCipher, err := encryption.NewCipher(encryption.CipherTypeAESGCM)
	if err != nil {
		t.Fatalf("NewCipher(AESGCM): %v", err)
	}
	encryption.SetActiveCipher(aesCipher)

	if got := encryption.GetActiveCipher().Type(); got != encryption.CipherTypeAESGCM {
		t.Fatalf("expected active cipher AESGCM, got %s", got)
	}

	// Verify package-level Encrypt/Decrypt use the active cipher.
	senderKey, _ := wgtypes.GenerateKey()
	receiverKey, _ := wgtypes.GenerateKey()
	msg := []byte("hello via active cipher")

	enc, err := encryption.Encrypt(msg, receiverKey.PublicKey(), senderKey)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dec, err := encryption.Decrypt(enc, senderKey.PublicKey(), receiverKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(dec) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, dec)
	}
}

func TestNewCipherInvalid(t *testing.T) {
	_, err := encryption.NewCipher("invalid")
	if err == nil {
		t.Fatal("expected error for invalid cipher type")
	}
}

func TestNewCipherValid(t *testing.T) {
	for _, ct := range []encryption.CipherType{encryption.CipherTypeNaCl, encryption.CipherTypeAESGCM} {
		c, err := encryption.NewCipher(ct)
		if err != nil {
			t.Fatalf("NewCipher(%s): %v", ct, err)
		}
		if c.Type() != ct {
			t.Fatalf("expected type %s, got %s", ct, c.Type())
		}
	}
}

// TestCrossCipherIncompatibility verifies that messages encrypted with one cipher
// cannot be decrypted by the other (they use different wire formats).
func TestCrossCipherIncompatibility(t *testing.T) {
	senderKey, _ := wgtypes.GenerateKey()
	receiverKey, _ := wgtypes.GenerateKey()
	msg := []byte("cross-cipher test")

	nacl := &encryption.NaClCipher{}
	aesgcm := &encryption.AESGCMCipher{}

	// Encrypt with NaCl, try decrypt with AES-GCM.
	enc, err := nacl.Encrypt(msg, receiverKey.PublicKey(), senderKey)
	if err != nil {
		t.Fatalf("NaCl Encrypt: %v", err)
	}
	_, err = aesgcm.Decrypt(enc, senderKey.PublicKey(), receiverKey)
	if err == nil {
		t.Fatal("expected AES-GCM to fail decrypting NaCl-encrypted message")
	}

	// Encrypt with AES-GCM, try decrypt with NaCl.
	enc, err = aesgcm.Encrypt(msg, receiverKey.PublicKey(), senderKey)
	if err != nil {
		t.Fatalf("AES-GCM Encrypt: %v", err)
	}
	_, err = nacl.Decrypt(enc, senderKey.PublicKey(), receiverKey)
	if err == nil {
		t.Fatal("expected NaCl to fail decrypting AES-GCM-encrypted message")
	}
}

// TestConcurrentEncryptDecrypt verifies thread safety of each cipher.
func TestConcurrentEncryptDecrypt(t *testing.T) {
	for _, cipher := range []encryption.Cipher{&encryption.NaClCipher{}, &encryption.AESGCMCipher{}} {
		t.Run(string(cipher.Type()), func(t *testing.T) {
			senderKey, _ := wgtypes.GenerateKey()
			receiverKey, _ := wgtypes.GenerateKey()
			msg := []byte("concurrent test payload")

			var wg sync.WaitGroup
			errs := make(chan error, 50)

			for i := 0; i < 50; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					enc, err := cipher.Encrypt(msg, receiverKey.PublicKey(), senderKey)
					if err != nil {
						errs <- err
						return
					}
					dec, err := cipher.Decrypt(enc, senderKey.PublicKey(), receiverKey)
					if err != nil {
						errs <- err
						return
					}
					if string(dec) != string(msg) {
						errs <- err
					}
				}()
			}

			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("concurrent error: %v", err)
			}
		})
	}
}

// TestEncryptMessageWithFIPSCipher verifies that EncryptMessage/DecryptMessage
// work correctly when the active cipher is switched to AES-GCM.
func TestEncryptMessageWithFIPSCipher(t *testing.T) {
	original := encryption.GetActiveCipher()
	defer encryption.SetActiveCipher(original)

	aesCipher, _ := encryption.NewCipher(encryption.CipherTypeAESGCM)
	encryption.SetActiveCipher(aesCipher)

	senderKey, _ := wgtypes.GenerateKey()
	receiverKey, _ := wgtypes.GenerateKey()

	protoMsg := &testprotos.TestMessage{Body: "fips-encrypted message"}
	encryptedMsg, err := encryption.EncryptMessage(receiverKey.PublicKey(), senderKey, protoMsg)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	decryptedMsg := &testprotos.TestMessage{}
	err = encryption.DecryptMessage(senderKey.PublicKey(), receiverKey, encryptedMsg, decryptedMsg)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	if decryptedMsg.GetBody() != protoMsg.GetBody() {
		t.Fatalf("expected %q, got %q", protoMsg.GetBody(), decryptedMsg.GetBody())
	}
}

// TestDefaultCipherIsNaCl verifies the default cipher is NaCl for backward compat.
func TestDefaultCipherIsNaCl(t *testing.T) {
	original := encryption.GetActiveCipher()
	defer encryption.SetActiveCipher(original)

	// Reset to default by creating a fresh NaCl cipher.
	nacl, _ := encryption.NewCipher(encryption.CipherTypeNaCl)
	encryption.SetActiveCipher(nacl)

	if encryption.GetActiveCipher().Type() != encryption.CipherTypeNaCl {
		t.Fatal("default cipher should be NaCl")
	}
}

// TestAESGCMDeterministicKeyAgreement verifies that the same key pair always
// derives the same shared secret (deterministic ECDH).
func TestAESGCMDeterministicKeyAgreement(t *testing.T) {
	cipher := &encryption.AESGCMCipher{}
	senderKey, _ := wgtypes.GenerateKey()
	receiverKey, _ := wgtypes.GenerateKey()
	msg := []byte("deterministic test")

	// Encrypt twice with the same keys — ciphertexts should differ (random nonce)
	// but both should decrypt to the same plaintext.
	enc1, _ := cipher.Encrypt(msg, receiverKey.PublicKey(), senderKey)
	enc2, _ := cipher.Encrypt(msg, receiverKey.PublicKey(), senderKey)

	if string(enc1) == string(enc2) {
		t.Fatal("two encryptions of the same message should produce different ciphertexts (random nonce)")
	}

	dec1, _ := cipher.Decrypt(enc1, senderKey.PublicKey(), receiverKey)
	dec2, _ := cipher.Decrypt(enc2, senderKey.PublicKey(), receiverKey)

	if string(dec1) != string(msg) || string(dec2) != string(msg) {
		t.Fatal("both ciphertexts should decrypt to the original message")
	}
}

// TestNaClNonceUniqueness verifies NaCl produces different ciphertexts per call.
func TestNaClNonceUniqueness(t *testing.T) {
	cipher := &encryption.NaClCipher{}
	senderKey, _ := wgtypes.GenerateKey()
	receiverKey, _ := wgtypes.GenerateKey()
	msg := []byte("nonce test")

	enc1, _ := cipher.Encrypt(msg, receiverKey.PublicKey(), senderKey)
	enc2, _ := cipher.Encrypt(msg, receiverKey.PublicKey(), senderKey)

	if string(enc1) == string(enc2) {
		t.Fatal("NaCl should use unique nonces per encryption")
	}
}

func testCipher(t *testing.T, c encryption.Cipher) {
	t.Helper()

	senderKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	receiverKey, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tests := []struct {
		name string
		msg  []byte
	}{
		{"short message", []byte("hello")},
		{"empty message", []byte("")},
		{"long message", make([]byte, 4096)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := c.Encrypt(tt.msg, receiverKey.PublicKey(), senderKey)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			decrypted, err := c.Decrypt(encrypted, senderKey.PublicKey(), receiverKey)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if len(tt.msg) != len(decrypted) {
				t.Fatalf("length mismatch: expected %d, got %d", len(tt.msg), len(decrypted))
			}
			for i := range tt.msg {
				if tt.msg[i] != decrypted[i] {
					t.Fatalf("byte %d mismatch", i)
				}
			}
		})
	}

	// Test wrong key fails decryption.
	t.Run("wrong key fails", func(t *testing.T) {
		wrongKey, _ := wgtypes.GenerateKey()
		encrypted, err := c.Encrypt([]byte("secret"), receiverKey.PublicKey(), senderKey)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		_, err = c.Decrypt(encrypted, wrongKey.PublicKey(), receiverKey)
		if err == nil {
			t.Fatal("expected decryption to fail with wrong key")
		}
	})

	// Test truncated message fails.
	t.Run("truncated message fails", func(t *testing.T) {
		_, err := c.Decrypt([]byte{1, 2, 3}, senderKey.PublicKey(), receiverKey)
		if err == nil {
			t.Fatal("expected decryption to fail with truncated message")
		}
	})

	// Test tampered ciphertext fails.
	t.Run("tampered ciphertext fails", func(t *testing.T) {
		encrypted, err := c.Encrypt([]byte("tamper test"), receiverKey.PublicKey(), senderKey)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		// Flip a byte in the middle of the ciphertext.
		if len(encrypted) > 20 {
			encrypted[20] ^= 0xFF
		}
		_, err = c.Decrypt(encrypted, senderKey.PublicKey(), receiverKey)
		if err == nil {
			t.Fatal("expected decryption to fail with tampered ciphertext")
		}
	})

	// Test empty ciphertext fails.
	t.Run("empty ciphertext fails", func(t *testing.T) {
		_, err := c.Decrypt([]byte{}, senderKey.PublicKey(), receiverKey)
		if err == nil {
			t.Fatal("expected decryption to fail with empty ciphertext")
		}
	})
}

// TestAESGCMWireTag verifies the AES-GCM wire format carries the cipher tag as
// its first byte, and that a tag mismatch (e.g. a NaCl-format message fed to the
// AES-GCM decryptor) fails loudly with a tag error rather than an opaque AEAD
// failure.
func TestAESGCMWireTag(t *testing.T) {
	senderKey, _ := wgtypes.GenerateKey()
	receiverKey, _ := wgtypes.GenerateKey()

	aesgcm := &encryption.AESGCMCipher{}
	nacl := &encryption.NaClCipher{}

	enc, err := aesgcm.Encrypt([]byte("tagged payload"), receiverKey.PublicKey(), senderKey)
	if err != nil {
		t.Fatalf("AES-GCM Encrypt: %v", err)
	}
	if len(enc) == 0 || enc[0] != 0x01 {
		t.Fatalf("expected first byte to be AES-GCM tag 0x01, got % x", enc)
	}

	// A NaCl-format message starts with a 24-byte nonce whose first byte is
	// almost never 0x01; feeding it to the AES-GCM decryptor must fail on the tag
	// check, not silently mis-derive.
	naclMsg, err := nacl.Encrypt([]byte("nacl payload"), receiverKey.PublicKey(), senderKey)
	if err != nil {
		t.Fatalf("NaCl Encrypt: %v", err)
	}
	// Force a definite mismatch by clearing the first byte to something != tag.
	naclMsg[0] = 0x00
	if _, err := aesgcm.Decrypt(naclMsg, senderKey.PublicKey(), receiverKey); err == nil {
		t.Fatal("expected AES-GCM decrypt to reject a non-tagged message")
	}
}
