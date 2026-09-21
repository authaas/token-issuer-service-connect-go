//revive:disable:package-comments
package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	"buf.build/gen/go/authaas/identity-data/protocolbuffers/go/identity/data"
	"buf.build/gen/go/authaas/identity/protocolbuffers/go/identity"
	"buf.build/gen/go/authaas/token-issuer-service/protocolbuffers/go/token/issuer"
	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
	"github.com/authaas/identity-data-bindings-connect-go/identity/data/dataconnect"
	tokenjwt "github.com/authaas/token-jwt-go"

	"github.com/authaas/token-issuer-service-connect-go/internal/signing"
)

const (
	principalID = "01234567-89ab-cdef-0123-456789abcdef"
	audience    = "audience-under-test"
	issuerName  = "issuer-under-test"
)

// grant is the value a holder redeems. Thirty-two bytes from a secure source
// in the flow that issued it; a fixed one here so a test can hash it.
var grant = []byte("0123456789abcdef0123456789abcdef")

// minted is the fixed time of minting tests assert against.
var minted = time.Unix(1_700_000_000, 0)

// digest is what the data service holds for value.
func digest(value []byte) []byte {
	sum := sha256.Sum256(value)

	return sum[:]
}

// dataStub stands in for the identity data service. It answers GetGrantHash
// with stored, and records whether ClearGrant was attempted and with what.
type dataStub struct {
	dataconnect.UnimplementedServiceHandler

	stored        []byte
	getErr        error
	clearErr      error
	cleared       bool
	clearedDigest []byte
}

func (d *dataStub) GetGrantHash(context.Context, *data.GetGrantHashRequest) (*data.GetGrantHashResponse, error) {
	if d.getErr != nil {
		return nil, d.getErr
	}

	response := data.GetGrantHashResponse_builder{}

	if d.stored != nil {
		response.GrantHash = token.GrantHash_builder{Bytes: d.stored}.Build()
	}

	return response.Build(), nil
}

func (d *dataStub) ClearGrant(_ context.Context, req *data.ClearGrantRequest) (*data.ClearGrantResponse, error) {
	d.cleared = true
	d.clearedDigest = req.GetGrantHash().GetBytes()

	if d.clearErr != nil {
		return nil, d.clearErr
	}

	return data.ClearGrantResponse_builder{}.Build(), nil
}

// answered is what the data service's client hands back when the service
// answered with code: a connect error marked as the peer's verdict.
func answered(code connect.Code, message string) error {
	return connect.NewError(code, message).WithRemote()
}

// keyPair generates a signing key and the public half to verify with.
func keyPair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	return private, public
}

// configuration is the signing material minting with private under algorithm.
func configuration(private ed25519.PrivateKey, algorithm string) signing.Configuration {
	return signing.Configuration{
		PrivateKey: signing.Key{PrivateKey: private},
		Algorithm:  algorithm,
		Audience:   audience,
		Issuer:     issuerName,
	}
}

// newServer builds a server signing with private, against stub, minting at a
// fixed time.
func newServer(private ed25519.PrivateKey, stub *dataStub) *Server {
	server := New(stub, configuration(private, "EdDSA"))

	server.now = func() time.Time { return minted }

	return server
}

// request builds an IssueRequest presenting value for the principal.
func request(value []byte, expiresAt, notBefore *int64) *issuer.IssueRequest {
	return issuer.IssueRequest_builder{
		Proof: token.Proof_builder{
			Principal: identity.Principal_builder{Id: principalID}.Build(),
			Grant:     token.Grant_builder{Bytes: value}.Build(),
		}.Build(),
		ExpiresAt: expiresAt,
		NotBefore: notBefore,
	}.Build()
}

// decode verifies a minted token with public and answers with its claims.
func decode(t *testing.T, signed string, public ed25519.PublicKey) *token.JWT {
	t.Helper()

	claims := &tokenjwt.Claims{}

	_, err := jwtv5.ParseWithClaims(signed, claims, func(*jwtv5.Token) (any, error) {
		return public, nil
	}, jwtv5.WithValidMethods([]string{"EdDSA"}))
	if err != nil {
		t.Fatalf("expected the minted token to verify, got %v", err)
	}

	return (*token.JWT)(claims)
}

// assertCode fails the test unless err is a connect error carrying want, and
// one this service authored: a remote error returned as the handler's own is
// scrubbed to Internal on the wire, so a verdict from the data service passed
// through would reach no caller as the code asserted here.
func assertCode(t *testing.T, err error, want connect.Code) *connect.Error {
	t.Helper()

	if err == nil {
		t.Fatalf("expected %v, got no error", want)
	}

	if got := connect.CodeOf(err); got != want {
		t.Errorf("expected %v, got %v", want, got)
	}

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected a connect error, got %v", err)
	}

	if connectErr.IsRemote() {
		t.Errorf("expected an error authored here, got the data service's: %v", err)
	}

	return connectErr
}
