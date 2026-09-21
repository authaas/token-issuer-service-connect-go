// The token issuer service: token.issuer.Service served with connect-go over
// the identity data service.
package main

import (
	"os"

	"github.com/authaas/token-issuer-service-connect-go/internal/cli"
)

func main() {
	os.Exit(cli.Run())
}
