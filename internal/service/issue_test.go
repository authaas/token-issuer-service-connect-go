//revive:disable:package-comments
package service

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

// preconditionFailure decodes the one PreconditionFailure detail a refusal
// carries.
func preconditionFailure(t *testing.T, err *connect.Error) *errdetails.PreconditionFailure {
	t.Helper()

	details := err.Details()
	if len(details) != 1 {
		t.Fatalf("details = %v, want one PreconditionFailure", details)
	}

	message, unmarshalErr := connectproto.UnmarshalErrorDetail(details[0])
	if unmarshalErr != nil {
		t.Fatalf("detail %s did not decode: %v", details[0].Type, unmarshalErr)
	}

	failure, ok := message.(*errdetails.PreconditionFailure)
	if !ok {
		t.Fatalf("detail = %T, want *errdetails.PreconditionFailure", message)
	}

	return failure
}

func TestIssue(t *testing.T) {
	t.Run("mints for a matching grant, after clearing it", func(t *testing.T) {
		private, public := keyPair(t)
		stub := &dataStub{stored: digest(grant)}

		response, err := newServer(private, stub).Issue(t.Context(), request(grant, nil, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !stub.cleared {
			t.Fatal("expected the grant to be cleared before minting")
		}

		// The digest is what clears: the data service swaps on it and never
		// sees the grant.
		if !bytes.Equal(stub.clearedDigest, digest(grant)) {
			t.Errorf("expected the digest to be presented for clearing, got %x", stub.clearedDigest)
		}

		claims := decode(t, response.GetToken(), public)

		if claims.GetSub() != principalID {
			t.Errorf("expected sub %q, got %q", principalID, claims.GetSub())
		}

		if claims.GetIat() != minted.Unix() {
			t.Errorf("expected iat %d, got %d", minted.Unix(), claims.GetIat())
		}
	})

	t.Run("names the configured audience and issuer, whatever the caller sends", func(t *testing.T) {
		private, public := keyPair(t)

		response, err := newServer(private, &dataStub{stored: digest(grant)}).
			Issue(t.Context(), request(grant, nil, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		claims := decode(t, response.GetToken(), public)

		if aud := claims.GetAud(); len(aud) != 1 || aud[0] != audience {
			t.Errorf("expected the configured audience, got %v", aud)
		}

		if claims.GetIss() != issuerName {
			t.Errorf("expected the configured issuer, got %q", claims.GetIss())
		}
	})

	t.Run("mints a token with no exp when none was supplied", func(t *testing.T) {
		private, public := keyPair(t)

		response, err := newServer(private, &dataStub{stored: digest(grant)}).
			Issue(t.Context(), request(grant, nil, nil))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if claims := decode(t, response.GetToken(), public); claims.HasExp() {
			t.Errorf("expected no exp, got %d", claims.GetExp())
		}
	})

	t.Run("mints with the supplied exp and nbf", func(t *testing.T) {
		private, public := keyPair(t)

		// Past the fixed time of minting for validation, and past the real
		// time for the verification decode runs.
		expires := time.Now().Add(time.Hour).Unix()
		notBefore := minted.Add(-time.Minute).Unix()

		response, err := newServer(private, &dataStub{stored: digest(grant)}).
			Issue(t.Context(), request(grant, &expires, &notBefore))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		claims := decode(t, response.GetToken(), public)

		if !claims.HasExp() || claims.GetExp() != expires {
			t.Errorf("expected exp %d, got %v", expires, claims.Exp)
		}

		if !claims.HasNbf() || claims.GetNbf() != notBefore {
			t.Errorf("expected nbf %d, got %v", notBefore, claims.Nbf)
		}
	})

	t.Run("refuses a grant that does not match, and clears nothing", func(t *testing.T) {
		private, _ := keyPair(t)
		stub := &dataStub{stored: digest(grant)}

		_, err := newServer(private, stub).Issue(
			t.Context(), request([]byte("something else entirely"), nil, nil),
		)

		refused := assertCode(t, err, connect.CodeFailedPrecondition)

		if refused.Message() != "grant not redeemed" {
			t.Errorf("message = %q, want %q", refused.Message(), "grant not redeemed")
		}

		failure := preconditionFailure(t, refused)

		if got := failure.GetViolations()[0].GetType(); got != "GRANT_NOT_REDEEMED" {
			t.Errorf("violation type = %q, want GRANT_NOT_REDEEMED", got)
		}

		// Reading precedes clearing, so nonsense destroys no grant someone else
		// is about to redeem.
		if stub.cleared {
			t.Fatal("expected no clear to be attempted for a grant that does not match")
		}
	})

	t.Run("refuses when no grant is outstanding", func(t *testing.T) {
		private, _ := keyPair(t)
		stub := &dataStub{stored: nil}

		_, err := newServer(private, stub).Issue(t.Context(), request(grant, nil, nil))

		assertCode(t, err, connect.CodeFailedPrecondition)

		if stub.cleared {
			t.Fatal("expected no clear to be attempted")
		}
	})

	t.Run("refuses when the clear does not land, and mints nothing", func(t *testing.T) {
		private, _ := keyPair(t)
		stub := &dataStub{
			stored:   digest(grant),
			clearErr: answered(connect.CodeFailedPrecondition, "grant not cleared"),
		}

		response, err := newServer(private, stub).Issue(t.Context(), request(grant, nil, nil))

		assertCode(t, err, connect.CodeFailedPrecondition)

		if response != nil {
			t.Fatal("expected nothing to be minted when the clear did not land")
		}
	})

	t.Run("refuses a principal with no identity", func(t *testing.T) {
		private, _ := keyPair(t)
		stub := &dataStub{getErr: answered(connect.CodeNotFound, "identity not found")}

		_, err := newServer(private, stub).Issue(t.Context(), request(grant, nil, nil))

		assertCode(t, err, connect.CodeFailedPrecondition)
	})

	t.Run("refuses with Unavailable while no data replica is held", func(t *testing.T) {
		private, _ := keyPair(t)
		// What the holding transport answers while discovery has given it no
		// address.
		stub := &dataStub{getErr: connect.NewError(connect.CodeUnavailable, "no upstream address discovered")}

		_, err := newServer(private, stub).Issue(t.Context(), request(grant, nil, nil))

		unavailable := assertCode(t, err, connect.CodeUnavailable)

		if unavailable.Message() != "identity data service unavailable" {
			t.Errorf("message = %q, want %q", unavailable.Message(), "identity data service unavailable")
		}
	})

	t.Run("refuses when the data service fails to answer", func(t *testing.T) {
		private, _ := keyPair(t)
		stub := &dataStub{getErr: errors.New("connection reset")}

		_, err := newServer(private, stub).Issue(t.Context(), request(grant, nil, nil))

		assertCode(t, err, connect.CodeInternal)
	})

	t.Run("refuses a principal the data service rejects as malformed", func(t *testing.T) {
		private, _ := keyPair(t)
		stub := &dataStub{getErr: answered(connect.CodeInvalidArgument, "validation failed")}

		_, err := newServer(private, stub).Issue(t.Context(), request(grant, nil, nil))

		assertCode(t, err, connect.CodeInvalidArgument)
	})

	t.Run("refuses when the clear fails for another reason", func(t *testing.T) {
		private, _ := keyPair(t)
		stub := &dataStub{stored: digest(grant), clearErr: errors.New("connection reset")}

		_, err := newServer(private, stub).Issue(t.Context(), request(grant, nil, nil))

		assertCode(t, err, connect.CodeInternal)
	})

	t.Run("refuses a request presenting no grant", func(t *testing.T) {
		private, _ := keyPair(t)

		_, err := newServer(private, &dataStub{}).Issue(t.Context(), request(nil, nil, nil))

		assertCode(t, err, connect.CodeInvalidArgument)
	})

	t.Run("refuses an exp in the past", func(t *testing.T) {
		private, _ := keyPair(t)
		expired := minted.Add(-time.Hour).Unix()

		_, err := newServer(private, &dataStub{}).Issue(t.Context(), request(grant, &expired, nil))

		assertCode(t, err, connect.CodeInvalidArgument)
	})

	t.Run("refuses when the key cannot sign with the configured algorithm", func(t *testing.T) {
		private, _ := keyPair(t)

		server := New(&dataStub{stored: digest(grant)}, configuration(private, "RS256"))

		_, err := server.Issue(t.Context(), request(grant, nil, nil))

		assertCode(t, err, connect.CodeInternal)
	})
}
