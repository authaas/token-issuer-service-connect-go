//revive:disable:package-comments
package service

import (
	"time"

	"github.com/authaas/identity-data-bindings-connect-go/identity/data/dataconnect"
	"github.com/authaas/token-issuer-service-bindings-connect-go/token/issuer/issuerconnect"
	"github.com/authaas/token-issuer-service-connect-go/internal/signing"
)

// Server serves token.issuer.Service over the identity data service.
//
// It holds the signing key and is the only service that signs. It keeps no
// state between requests and names no subject of its own: every token it
// produces names a subject it established a claim to during that request.
type Server struct {
	issuerconnect.UnimplementedServiceHandler

	data    dataconnect.ServiceClient
	signing signing.Configuration
	now     func() time.Time
}

// New returns a Server over data, minting with signing.
func New(data dataconnect.ServiceClient, signing signing.Configuration) *Server {
	return &Server{data: data, signing: signing, now: time.Now}
}
