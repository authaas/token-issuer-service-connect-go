//revive:disable:package-comments
package validate

import (
	"testing"
	"time"
)

func TestExpiresAt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("accepts an omitted expiration", func(t *testing.T) {
		if violations := ExpiresAt(nil, now); len(violations) != 0 {
			t.Errorf("expected no violations, got %v", violations)
		}
	})

	t.Run("accepts an expiration in the future", func(t *testing.T) {
		future := now.Add(time.Hour).Unix()

		if violations := ExpiresAt(&future, now); len(violations) != 0 {
			t.Errorf("expected no violations, got %v", violations)
		}
	})

	for name, value := range map[string]int64{
		"in the past":  now.Add(-time.Hour).Unix(),
		"now":          now.Unix(),
		"at the epoch": 0,
		"negative":     -1,
	} {
		t.Run("refuses an expiration "+name, func(t *testing.T) {
			violations := ExpiresAt(&value, now)

			if len(violations) != 1 {
				t.Fatalf("expected one violation, got %v", violations)
			}

			if violations[0].Field != "expires_at" {
				t.Errorf("expected field expires_at, got %q", violations[0].Field)
			}
		})
	}
}
