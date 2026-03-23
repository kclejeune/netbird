package encryption_test

import (
	"testing"

	"github.com/netbirdio/netbird/encryption"
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
}
