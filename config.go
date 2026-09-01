package accessaudit

import (
	"time"

	azugocfg "azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"

	"github.com/gmb-lib/go-authbyte/authclient"
	pkconfig "github.com/gmb-lib/go-platform-kit/config"
)

// Store backends.
const (
	StoreBackendPostgres = "postgres"
	StoreBackendMemory   = "memory"
)

// Configuration is the access-audit service configuration. It mirrors the
// platform azugo service convention: the squashed base configuration plus a
// go-authbyte inbound auth sub-config and the access-log-specific settings.
type Configuration struct {
	*pkconfig.BaseConfiguration `mapstructure:",squash"`

	// Auth is the go-authbyte inbound DPoP validation config
	// (AUTH_ISSUER_URL / SERVICE_AUDIENCE=svc:access-audit / …).
	Auth *authclient.Configuration `mapstructure:"auth"`

	// StoreDSN selects + configures the PostgreSQL backend (the `access_audit`
	// schema reached via SECURITY DEFINER procedures). When set it is used;
	// otherwise the in-memory backend is used (development/test only). Points at
	// the EXECUTE-only `access_audit_public` role; source it from Vault in
	// production (it carries a password).
	StoreDSN string `mapstructure:"access_audit_store_dsn"`

	// SealKey is the HMAC-SHA256 key for per-row seals + per-period checkpoints.
	// It is held in memory only and NEVER persisted with
	// the records. Source it from Vault in production; rotate via re-sealing (a
	// future op). Minimum 32 bytes.
	SealKey string `mapstructure:"access_audit_seal_key" validate:"required,min=32"`

	// System is the optional tenant/system dimension stamped on every record
	// (defaults to single-system "default").
	System string `mapstructure:"access_audit_system" validate:"required"`

	// RetentionInterval is how often the retention sweep runs (checkpoint closed
	// periods, then purge expired ones).
	RetentionInterval time.Duration `mapstructure:"access_audit_retention_interval" validate:"required,gt=0"`
	// RetentionWindow is the accountability window: records in periods older than
	// now-RetentionWindow are purged (unless under legal hold). Concrete value is
	// a DPO decision; the default is a conservative 365 days.
	RetentionWindow time.Duration `mapstructure:"access_audit_retention_window" validate:"required,gt=0"`

	// VerifyRetentionDays is the retention window (days) for the purpose-scoped
	// verify abuse-evidence store — it carries IP/user-agent (personal data), so
	// the window keeps holding them proportionate. Swept on the same schedule as
	// the access-record retention.
	VerifyRetentionDays int `mapstructure:"verify_audit_retention_days" validate:"required,gt=0"`
}

// NewConfiguration returns the configuration skeleton for binding.
func NewConfiguration() *Configuration {
	return &Configuration{BaseConfiguration: pkconfig.New()}
}

// ServerCore returns the embedded azugo configuration.
func (c *Configuration) ServerCore() *azugocfg.Configuration {
	return c.Configuration
}

// Bind registers defaults and environment bindings.
func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.BaseConfiguration.Bind("", v)
	c.Auth = azugocfg.Bind(c.Auth, "auth", v)

	v.SetDefault("access_audit_system", "default")
	v.SetDefault("access_audit_retention_interval", 24*time.Hour)
	v.SetDefault("access_audit_retention_window", 365*24*time.Hour)
	v.SetDefault("verify_audit_retention_days", 90)

	// The seal key is a secret — prefer the remote secret store (Vault).
	if key, err := corecfg.LoadRemoteSecret("ACCESS_AUDIT_SEAL_KEY"); err == nil && key != "" {
		v.SetDefault("access_audit_seal_key", key)
	}

	_ = v.BindEnv("access_audit_store_dsn", "ACCESS_AUDIT_STORE_DSN")
	_ = v.BindEnv("access_audit_seal_key", "ACCESS_AUDIT_SEAL_KEY")
	_ = v.BindEnv("access_audit_system", "ACCESS_AUDIT_SYSTEM")
	_ = v.BindEnv("access_audit_retention_interval", "ACCESS_AUDIT_RETENTION_INTERVAL")
	_ = v.BindEnv("access_audit_retention_window", "ACCESS_AUDIT_RETENTION_WINDOW")
	_ = v.BindEnv("verify_audit_retention_days", "VERIFY_AUDIT_RETENTION_DAYS")
}

// Validate validates the configuration.
func (c *Configuration) Validate(valid *validation.Validate) error {
	if err := c.BaseConfiguration.Validate(valid); err != nil {
		return err
	}
	if err := valid.Struct(c); err != nil {
		return err
	}

	return c.Auth.Validate(valid)
}

// StoreBackend derives the store backend from configuration.
func (c *Configuration) StoreBackend() string {
	if c.StoreDSN != "" {
		return StoreBackendPostgres
	}

	return StoreBackendMemory
}

// SealKeyBytes returns the raw HMAC key bytes.
func (c *Configuration) SealKeyBytes() []byte { return []byte(c.SealKey) }
