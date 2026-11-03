package accessaudit

import (
	"path/filepath"
	"strings"
	"testing"
)

// A secret file that is named but missing must stop the start. Left alone, the
// empty address would silently select the in-memory store in production.
func TestAMissingDatabaseAddressFileStopsTheStart(t *testing.T) {
	t.Setenv("ACCESS_AUDIT_STORE_DSN_FILE", filepath.Join(t.TempDir(), "absent"))

	err := boundConfiguration(t).Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "ACCESS_AUDIT_STORE_DSN_FILE") {
		t.Fatalf("Validate = %v, want an error naming ACCESS_AUDIT_STORE_DSN_FILE", err)
	}
}
