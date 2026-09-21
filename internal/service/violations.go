//revive:disable:package-comments
package service

import (
	"time"

	errors "github.com/pbrpc/connect-errors"

	"buf.build/gen/go/authaas/token-issuer-service/protocolbuffers/go/token/issuer"

	"github.com/authaas/token-issuer-service-connect-go/internal/validate"
)

// violations checks the request's own fields.
func violations(req *issuer.IssueRequest, now time.Time) []errors.FieldViolation {
	violations := validate.Grant(req.GetProof().GetGrant())
	violations = append(violations, validate.ExpiresAt(req.ExpiresAt, now)...)

	return append(violations, validate.NotBefore(req.NotBefore)...)
}
