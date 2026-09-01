// Package accessaudit is the eSignature-Portal access-audit service: the
// reusable GDPR-audit (GDPR personal-data access) sink. It synchronously accepts
// the access-record envelope from go-gdpr-audit producers, seals
// each record (per-row HMAC) into its own append-only, subject-indexed store,
// answers DSAR queries by data subject, verifies integrity, and runs the
// retention sweep (per-period checkpoints + windowed purge) — its own
// per-system deployment.
package accessaudit

import (
	"fmt"

	"azugo.io/azugo"
	"azugo.io/azugo/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-platform-kit/platform"

	"github.com/go-make-bytes/access-audit/events"
	"github.com/go-make-bytes/access-audit/seal"
	"github.com/go-make-bytes/access-audit/store"
	"github.com/go-make-bytes/access-audit/tasks"
)

// App is the access-audit application container.
type App struct {
	*azugo.App

	config *Configuration

	sealer     *seal.Sealer
	store      store.Store
	events     *events.Emitter
	authClient *authclient.Client
	authMW     azugo.RequestHandlerFunc
}

// New creates the application: configuration, platform cross-cutting setup, the
// HMAC sealer, the access-log store, inbound auth and the retention task.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := NewConfiguration()

	a, err := server.New(cmd, server.Options{
		AppName:       "Access Audit Service",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app := &App{App: a, config: config}
	if err := app.init(); err != nil {
		return nil, err
	}

	return app, nil
}

func (a *App) init() error {
	cfg := a.config

	if err := platform.Setup(a.App, platform.Options{
		Config: cfg.BaseConfiguration,
	}); err != nil {
		return err
	}

	a.events = events.New(a.Log())

	sealer, err := seal.New(cfg.SealKeyBytes())
	if err != nil {
		return fmt.Errorf("access-audit: seal: %w", err)
	}
	a.sealer = sealer

	switch cfg.StoreBackend() {
	case StoreBackendPostgres:
		a.store, err = store.NewPostgres(a.BackgroundContext(), cfg.StoreDSN)
		if err != nil {
			return err
		}
	default:
		a.Log().Warn("no store DSN configured (ACCESS_AUDIT_STORE_DSN) — using in-memory store; access records will NOT survive restarts (development only)")
		a.store = store.NewMemory()
	}

	a.authClient, err = authclient.New(cfg.Auth)
	if err != nil {
		return fmt.Errorf("access-audit: auth client: %w", err)
	}
	a.authMW = a.authClient.Authenticate()

	return a.AddTask(tasks.NewRetentionTask(tasks.RetentionConfig{
		Store:               a.store,
		Sealer:              a.sealer,
		Events:              a.events,
		Interval:            cfg.RetentionInterval,
		Window:              cfg.RetentionWindow,
		VerifyRetentionDays: cfg.VerifyRetentionDays,
		Logger:              a.Log(),
	}))
}

// Start verifies store connectivity (non-fatal) then starts the server and the
// retention task.
func (a *App) Start() error {
	if err := a.store.Ping(a.BackgroundContext()); err != nil {
		a.Log().Warn("access-audit store not reachable at start — readiness will report not-ready until it recovers", zap.Error(err))
	}

	return a.App.Start()
}

// Config returns the loaded configuration.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

// Store returns the access-log store.
func (a *App) Store() store.Store { return a.store }

// Sealer returns the HMAC sealer.
func (a *App) Sealer() *seal.Sealer { return a.sealer }

// Events returns the security-event emitter.
func (a *App) Events() *events.Emitter { return a.events }

// AuthMiddleware returns the inbound authentication middleware.
func (a *App) AuthMiddleware() azugo.RequestHandlerFunc { return a.authMW }

// SetAuthMiddleware overrides the inbound authentication middleware. Test use
// only — production wiring always uses the go-authbyte DPoP middleware.
func (a *App) SetAuthMiddleware(mw azugo.RequestHandlerFunc) { a.authMW = mw }
