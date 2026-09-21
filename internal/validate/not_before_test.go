//revive:disable:package-comments
package validate

import (
	"testing"
	"time"
)

func TestNotBefore(t *testing.T) {
	t.Run("accepts an omitted not-before", func(t *testing.T) {
		if violations := NotBefore(nil); len(violations) != 0 {
			t.Errorf("expected no violations, got %v", violations)
		}
	})

	for name, value := range map[string]int64{
		"in the future": time.Now().Add(time.Hour).Unix(),
		"now":           time.Now().Unix(),
		"in the past":   time.Now().Add(-time.Hour).Unix(),
		"at the epoch":  0,
	} {
		t.Run("accepts a not-before "+name, func(t *testing.T) {
			if violations := NotBefore(&value); len(violations) != 0 {
				t.Errorf("expected no violations, got %v", violations)
			}
		})
	}

	t.Run("refuses a negative not-before", func(t *testing.T) {
		negative := int64(-1)

		violations := NotBefore(&negative)

		if len(violations) != 1 {
			t.Fatalf("expected one violation, got %v", violations)
		}

		if violations[0].Field != "not_before" {
			t.Errorf("expected field not_before, got %q", violations[0].Field)
		}
	})
}
