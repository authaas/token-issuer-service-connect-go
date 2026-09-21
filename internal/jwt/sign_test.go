//revive:disable:package-comments
package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	tokenjwt "github.com/authaas/token-jwt-go"
)

func TestSign(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	claims := &token.JWT{Sub: "subject", Iat: time.Now().Unix()}

	t.Run("produces a token the matching public key verifies", func(t *testing.T) {
		signed, err := Sign(claims, private, "EdDSA")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		parsed := &tokenjwt.Claims{}

		_, err = jwtv5.ParseWithClaims(signed, parsed, func(*jwtv5.Token) (any, error) {
			return public, nil
		}, jwtv5.WithValidMethods([]string{"EdDSA"}))
		if err != nil {
			t.Fatalf("expected the token to verify, got %v", err)
		}

		if parsed.Sub != "subject" {
			t.Errorf("expected the subject to round-trip, got %q", parsed.Sub)
		}
	})

	t.Run("refuses an algorithm the library does not know", func(t *testing.T) {
		if _, err := Sign(claims, private, "XX999"); err == nil {
			t.Fatal("expected an unknown algorithm to be refused")
		}
	})

	t.Run("refuses a key the algorithm cannot sign with", func(t *testing.T) {
		if _, err := Sign(claims, private, "RS256"); err == nil {
			t.Fatal("expected an ed25519 key to be refused for RS256")
		}
	})
}
