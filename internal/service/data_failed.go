//revive:disable:package-comments
package service

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
	errors "github.com/pbrpc/connect-errors"

	"github.com/authaas/token-issuer-service-bindings-connect-go/token/issuer/issuerconnect"
)

// dataFailed maps a failure reaching the identity data service. An unknown
// or malformed principal is the caller's problem, since the principal is
// passed on verbatim; anything else is ours. A transport with no replica held
// answers Unavailable on its own, so that case needs no sentinel.
//
// Every answer is authored here. The error in hand came from another service,
// and connect answers Internal with no message for a remote error a handler
// returns as it is.
func dataFailed(ctx context.Context, log *slog.Logger, action string, err error) error {
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable:
		log.WarnContext(ctx, "Identity data service unavailable", "error", err)
		return connect.NewError(connect.CodeUnavailable, "identity data service unavailable")
	case connect.CodeNotFound:
		return refuse(ctx, log, "unknown_principal", "no identity exists for the principal")
	case connect.CodeInvalidArgument:
		return errors.InvalidArgument(ctx, "validation failed", errors.FieldViolation{
			Field:       "proof.principal.id",
			Description: "is not a UUID",
		})
	default:
		log.ErrorContext(ctx, "Failed to "+action, "error", err)
		return errors.Internal(ctx, "failed to "+action, "DATA_FAILED", issuerconnect.ServiceName)
	}
}
