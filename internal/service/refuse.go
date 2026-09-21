//revive:disable:package-comments
package service

import (
	"context"
	"log/slog"

	errors "github.com/pbrpc/connect-errors"
)

// refuse reports why the grant was not redeemed.
func refuse(ctx context.Context, log *slog.Logger, reason, message string) error {
	log.InfoContext(ctx, "Token refused", "reason", reason)

	return errors.PreconditionFailed(ctx, "grant not redeemed", "GRANT_NOT_REDEEMED", "proof.grant", message)
}
