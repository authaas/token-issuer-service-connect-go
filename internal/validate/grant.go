//revive:disable:package-comments
package validate

import (
	errors "github.com/pbrpc/connect-errors"

	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
)

// Grant validates a presented grant: there must be one.
func Grant(grant *token.Grant) []errors.FieldViolation {
	if len(grant.GetBytes()) > 0 {
		return nil
	}

	return []errors.FieldViolation{{
		Field:       "proof.grant.bytes",
		Description: "is required",
	}}
}
