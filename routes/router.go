// Package routes registers the access-audit HTTP API.
package routes

import (
	"azugo.io/azugo"
	corehttp "azugo.io/core/http"

	accessaudit "github.com/go-make-bytes/access-audit"
)

type router struct {
	*accessaudit.App
}

// Init registers all routes.
func Init(a *accessaudit.App) error {
	r := &router{App: a}

	// Public liveness/readiness.
	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	// Authenticated API (go-authbyte DPoP service tokens).
	v1 := a.Group("/v1")
	v1.Use(a.AuthMiddleware())

	// Write — producers (go-gdpr-audit) post access records here.
	v1.Post("/access-records", r.recordAccess)
	// Write — the purpose-scoped verify abuse-evidence surface (own schema,
	// lawful basis and retention; scope group verify-audit).
	v1.Post("/verify-events", r.recordVerifyEvent)
	// Read — DSAR: every access to a data subject's personal data.
	v1.Get("/subjects/{subject}/access-records", r.subjectRecords)
	// Admin — integrity verification, legal holds, manual purge.
	v1.Get("/verify", r.verify)
	v1.Post("/legal-holds", r.placeLegalHold)
	v1.Delete("/legal-holds/{subject}", r.clearLegalHold)
	v1.Post("/purge", r.purge)

	return nil
}

// requireScope enforces an access-audit:<level> scope; on denial it emits the
// platform authz.denied security event and returns false.
//
//	write — producers recording access (svc tokens)
//	read — DSAR / DPO reads
//	admin — verify, legal holds, manual purge
func (r *router) requireScope(ctx *azugo.Context, level string) bool {
	if ctx.User().HasScopeLevel("access-audit", level) {
		return true
	}

	r.Events().AuthzDenied(ctx, "access-audit:"+level, ctx.User().ID(), ctx.Path())
	ctx.Error(corehttp.ForbiddenError{})

	return false
}
