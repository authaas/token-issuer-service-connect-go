//revive:disable:package-comments
package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"

	"connectrpc.com/connect/v2"
	errors "github.com/pbrpc/connect-errors"

	"buf.build/gen/go/authaas/identity-data/protocolbuffers/go/identity/data"
	"buf.build/gen/go/authaas/token-issuer-service/protocolbuffers/go/token/issuer"
	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	"git.sonicoriginal.software/logger"

	"github.com/authaas/token-issuer-service-bindings-connect-go/token/issuer/issuerconnect"
	"github.com/authaas/token-issuer-service-connect-go/internal/jwt"
)

// Issue mints a token for the principal whose outstanding grant the caller
// presented.
//
// It reads the stored digest, compares it to the digest of the presented grant
// in constant time, clears the grant by that digest, and mints only once the
// clear lands. The comparison is here rather than in the data service because
// this service is what mints: a service that mints on an answer it was handed
// holds no proof of its own.
//
// Failure detail is not withheld. Every refusal follows from a grant the caller
// presented, so it tells the caller nothing it did not already know.
func (s *Server) Issue(
	ctx context.Context,
	req *issuer.IssueRequest,
) (*issuer.IssueResponse, error) {
	log := logger.FromContext(ctx)
	now := s.now()

	if violations := violations(req, now); len(violations) > 0 {
		return nil, errors.InvalidArgument(ctx, "validation failed", violations...)
	}

	principal := req.GetProof().GetPrincipal()
	log = log.With("principal", principal.GetId())

	gh := data.GetGrantHashRequest_builder{Principal: principal}.Build()
	stored, err := s.data.GetGrantHash(ctx, gh)
	if err != nil {
		return nil, dataFailed(ctx, log, "read the grant hash", err)
	}

	if !stored.HasGrantHash() {
		err = refuse(ctx, log,
			"no_grant", "no grant is outstanding for the principal")
		return nil, err
	}

	digest := sha256.Sum256(req.GetProof().GetGrant().GetBytes())

	if subtle.ConstantTimeCompare(stored.GetGrantHash().GetBytes(), digest[:]) != 1 {
		err = refuse(ctx, log,
			"mismatch", "grant does not match the outstanding grant")
		return nil, err
	}

	// Only after the comparison, so a caller presenting nonsense destroys no
	// grant someone else is about to redeem.
	clear := data.ClearGrantRequest_builder{
		Principal: principal,
		GrantHash: token.GrantHash_builder{Bytes: digest[:]}.Build(),
	}.Build()

	if _, err = s.data.ClearGrant(ctx, clear); err != nil {
		if connect.CodeOf(err) == connect.CodeFailedPrecondition {
			err = refuse(ctx, log,
				"not_cleared", "grant was replaced before it could be redeemed")
			return nil, err
		}

		return nil, dataFailed(ctx, log, "clear the grant", err)
	}

	claims := jwt.Claims(
		principal.GetId(),
		s.signing.Audience,
		s.signing.Issuer,
		req.ExpiresAt,
		req.NotBefore,
		now,
	)

	signed, err := jwt.Sign(
		claims,
		s.signing.PrivateKey.PrivateKey,
		s.signing.Algorithm,
	)
	if err != nil {
		log.ErrorContext(ctx, "Failed to sign", "error", err)
		return nil, errors.Internal(ctx,
			"failed to sign token",
			"SIGNING_FAILED",
			issuerconnect.ServiceName,
		)
	}

	log.InfoContext(ctx, "Token issued", issued(claims)...)

	return issuer.IssueResponse_builder{Token: signed}.Build(), nil
}
