package accessaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"
)

// boundConfiguration reads the configuration from the environment the way the
// service does at start.
func boundConfiguration(t *testing.T) *Configuration {
	t.Helper()

	c := NewConfiguration()
	v := viper.New()
	c.Bind("", v)
	qt.Assert(t, qt.IsNil(v.Unmarshal(c)))

	return c
}

// The connection string carries the database role's password, so it may arrive
// as a file the secret store's agent writes (ACCESS_AUDIT_STORE_DSN_FILE).
func TestTheStoreAddressIsReadFromAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dsn")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte("postgres://access_audit_public:pw@db:5432/fleet\n"), 0o600)))
	t.Setenv("ACCESS_AUDIT_STORE_DSN_FILE", path)

	qt.Check(t, qt.Equals(boundConfiguration(t).StoreDSN, "postgres://access_audit_public:pw@db:5432/fleet"))
}

// An explicit environment value still wins over the file.
func TestTheStoreAddressFromTheEnvironmentWinsOverTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dsn")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte("postgres://from-file"), 0o600)))
	t.Setenv("ACCESS_AUDIT_STORE_DSN_FILE", path)
	t.Setenv("ACCESS_AUDIT_STORE_DSN", "postgres://from-env")

	qt.Check(t, qt.Equals(boundConfiguration(t).StoreDSN, "postgres://from-env"))
}
