//revive:disable:package-comments
package validate

import (
	errors "github.com/pbrpc/connect-errors"
)

// NotBefore validates a supplied not-before. An omitted one is nil and takes
// the time of minting, so there is nothing to check. A supplied one may be in
// the past, which activates the token immediately, but not before the epoch.
func NotBefore(notBefore *int64) []errors.FieldViolation {
	if notBefore == nil || *notBefore >= 0 {
		return nil
	}

	return []errors.FieldViolation{{
		Field:       "not_before",
		Description: "cannot be negative",
	}}
}
