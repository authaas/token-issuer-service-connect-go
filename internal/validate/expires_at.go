//revive:disable:package-comments
package validate

import (
	"time"

	errors "github.com/pbrpc/connect-errors"
)

// ExpiresAt validates a supplied expiration. An omitted one is nil and mints a
// token that does not expire, so there is nothing to check.
func ExpiresAt(expiresAt *int64, now time.Time) []errors.FieldViolation {
	if expiresAt == nil || *expiresAt > now.Unix() {
		return nil
	}

	return []errors.FieldViolation{{
		Field:       "expires_at",
		Description: "must be in the future",
	}}
}
