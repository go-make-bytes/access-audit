package accessaudit

import (
	"testing"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"
	"github.com/go-quicktest/qt"
)

// TestApp builds an App for tests: in-memory store, a fixed dev seal key and a
// stub auth middleware driven by the X-Test-Scopes request header (production
// wiring always uses the go-authbyte DPoP middleware).
func TestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("SERVICE_NAME", "access-audit")
	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("AUTH_ISSUER_URL", "http://localhost:8080")
	tb.Setenv("SERVICE_AUDIENCE", "svc:access-audit")
	tb.Setenv("ACCESS_AUDIT_SEAL_KEY", "test-seal-key-not-a-secret-000000000000") // ≥32 bytes; dev only

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	app.SetAuthMiddleware(TestAuthMiddleware())

	return app
}

// TestAuthMiddleware authenticates requests from the X-Test-Scopes header
// (comma-separated scopes, e.g. "access-audit:write") and uses the optional
// X-Test-Sub header as the caller identity (default "svc:test-client").
// Requests without scopes are rejected 401 — mirroring the production contract.
func TestAuthMiddleware() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			scopes := ctx.Header.Get("X-Test-Scopes")
			if scopes == "" {
				ctx.StatusCode(401)
				ctx.Text("unauthorized")

				return
			}

			sub := ctx.Header.Get("X-Test-Sub")
			if sub == "" {
				sub = "svc:test-client"
			}

			ctx.SetUser(user.New(map[string]token.ClaimStrings{
				"sub":   {sub},
				"scope": {scopes},
			}))
			next(ctx)
		}
	}
}
