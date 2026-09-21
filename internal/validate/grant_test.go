//revive:disable:package-comments
package validate

import (
	"testing"

	"buf.build/gen/go/authaas/token/protocolbuffers/go/token"
)

func TestGrant(t *testing.T) {
	t.Run("accepts a grant with bytes", func(t *testing.T) {
		grant := token.Grant_builder{Bytes: []byte("0123456789abcdef0123456789abcdef")}.Build()

		if violations := Grant(grant); len(violations) != 0 {
			t.Errorf("expected no violations, got %v", violations)
		}
	})

	for name, grant := range map[string]*token.Grant{
		"absent": nil,
		"empty":  token.Grant_builder{}.Build(),
	} {
		t.Run("refuses a grant that is "+name, func(t *testing.T) {
			violations := Grant(grant)

			if len(violations) != 1 {
				t.Fatalf("expected one violation, got %v", violations)
			}

			if violations[0].Field != "proof.grant.bytes" {
				t.Errorf("expected field proof.grant.bytes, got %q", violations[0].Field)
			}
		})
	}
}
