//revive:disable:package-comments
package signing

// Configuration is the material a token is minted with.
type Configuration struct {
	// PrivateKey is the signing key. Nothing else holds it, so nothing else
	// produces a token this service would recognize as its own.
	PrivateKey Key `env:"TOKEN_SIGNING_KEY_PRIVATE,required"`

	// Algorithm names the signing method.
	Algorithm string `env:"TOKEN_SIGNING_ALG,required"`

	// Audience is the aud every minted token carries. A caller cannot choose
	// who its token claims to be for.
	Audience string `env:"TOKEN_AUDIENCE,required"`

	// Issuer is the iss every minted token carries.
	Issuer string `env:"TOKEN_ISSUER,required"`
}
