//revive:disable:package-comments
package jwt

import (
	"testing"
	"time"
)

func TestClaims(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("carries the subject, audience, issuer and time of minting", func(t *testing.T) {
		claims := Claims("subject", "audience", "issuer", nil, nil, now)

		if claims.GetSub() != "subject" || claims.GetIss() != "issuer" {
			t.Errorf("expected subject and issuer to be carried, got %+v", claims)
		}

		if aud := claims.GetAud(); len(aud) != 1 || aud[0] != "audience" {
			t.Errorf("expected the configured audience, got %v", aud)
		}

		if claims.GetIat() != now.Unix() {
			t.Errorf("expected iat %d, got %d", now.Unix(), claims.GetIat())
		}
	})

	t.Run("carries no exp when none was supplied", func(t *testing.T) {
		if claims := Claims("subject", "audience", "issuer", nil, nil, now); claims.HasExp() {
			t.Errorf("expected no exp, got %d", claims.GetExp())
		}
	})

	t.Run("carries the supplied exp", func(t *testing.T) {
		expires := now.Add(time.Hour).Unix()

		claims := Claims("subject", "audience", "issuer", &expires, nil, now)

		if !claims.HasExp() || claims.GetExp() != expires {
			t.Errorf("expected exp %d, got %v", expires, claims.Exp)
		}
	})

	t.Run("carries the time of minting as nbf when none was supplied", func(t *testing.T) {
		claims := Claims("subject", "audience", "issuer", nil, nil, now)

		if !claims.HasNbf() || claims.GetNbf() != now.Unix() {
			t.Errorf("expected nbf %d, got %v", now.Unix(), claims.Nbf)
		}
	})

	t.Run("carries the supplied nbf", func(t *testing.T) {
		later := now.Add(time.Minute).Unix()

		claims := Claims("subject", "audience", "issuer", nil, &later, now)

		if !claims.HasNbf() || claims.GetNbf() != later {
			t.Errorf("expected nbf %d, got %v", later, claims.Nbf)
		}
	})
}
