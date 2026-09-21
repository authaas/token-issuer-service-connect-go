//revive:disable:package-comments
package signing

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Key is a signing key, parsed from PEM-encoded PKCS #8.
type Key struct {
	crypto.PrivateKey
}

// UnmarshalText parses the key from its PEM encoding.
func (k *Key) UnmarshalText(text []byte) error {
	block, _ := pem.Decode(text)
	if block == nil {
		return errors.New("no PEM block found")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	k.PrivateKey = parsed

	return nil
}
