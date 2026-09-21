//revive:disable:package-comments
package jwt

import (
	"time"

	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
)

// Claims answers with the claims a token for subject carries.
//
// exp is carried as supplied, so a caller that supplied none mints a token
// with no expiration. nbf is the caller's, or the time of minting when none was
// supplied. iat is always the time of minting.
func Claims(subject, audience, issuer string, expiresAt, notBefore *int64, now time.Time) *token.JWT {
	minted := now.Unix()

	if notBefore == nil {
		notBefore = &minted
	}

	return &token.JWT{
		Sub: subject,
		Aud: []string{audience},
		Iss: issuer,
		Iat: minted,
		Exp: expiresAt,
		Nbf: notBefore,
	}
}
