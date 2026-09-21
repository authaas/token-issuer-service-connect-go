//revive:disable:package-comments
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/caarlos0/env/v11"
)

// privateKeyPEM generates a key and answers with its PEM encoding.
func privateKeyPEM(t *testing.T) string {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestKey(t *testing.T) {
	t.Run("parses the configured key", func(t *testing.T) {
		t.Setenv("TOKEN_SIGNING_KEY_PRIVATE", privateKeyPEM(t))
		t.Setenv("TOKEN_SIGNING_ALG", "EdDSA")
		t.Setenv("TOKEN_AUDIENCE", "audience-under-test")
		t.Setenv("TOKEN_ISSUER", "issuer-under-test")

		cfg, err := env.ParseAs[Configuration]()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, ok := cfg.PrivateKey.PrivateKey.(ed25519.PrivateKey); !ok {
			t.Errorf("key = %T, want ed25519.PrivateKey", cfg.PrivateKey.PrivateKey)
		}
	})

	t.Run("refuses a key that is not PEM", func(t *testing.T) {
		var key Key

		if err := key.UnmarshalText([]byte("not a pem block")); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("refuses a PEM block that is not a private key", func(t *testing.T) {
		var key Key

		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nonsense")})

		if err := key.UnmarshalText(block); err == nil {
			t.Error("expected an error")
		}
	})
}
