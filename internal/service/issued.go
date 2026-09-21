//revive:disable:package-comments
package service

import (
	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
)

// issued is what the log line for a minted token carries.
func issued(claims *token.JWT) []any {
	attrs := []any{
		"aud", claims.GetAud(), "iss", claims.GetIss(), "iat", claims.GetIat(), "nbf", claims.GetNbf(),
	}

	if claims.HasExp() {
		attrs = append(attrs, "exp", claims.GetExp())
	}

	return attrs
}
