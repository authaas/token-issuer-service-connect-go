//revive:disable:package-comments
package jwt

import (
	"crypto"
	"fmt"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	tokenjwt "github.com/authaas/token-jwt-go"
)

// Sign produces the token string for claims.
//
// algorithm names the signing method; the library refuses a key that cannot
// sign with it, so a mismatch surfaces here rather than as a token nothing
// verifies.
func Sign(claims *token.JWT, privateKey crypto.PrivateKey, algorithm string) (string, error) {
	method := jwtv5.GetSigningMethod(algorithm)
	if method == nil {
		return "", fmt.Errorf("unsupported algorithm %q", algorithm)
	}

	c := (*tokenjwt.Claims)(claims)
	unsigned := jwtv5.NewWithClaims(method, c)

	signed, err := unsigned.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	return signed, nil
}
