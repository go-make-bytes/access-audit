package routes

import (
	"time"

	"azugo.io/azugo"

	"github.com/go-make-bytes/access-audit/routes/request"
	"github.com/go-make-bytes/access-audit/routes/response"
	"github.com/go-make-bytes/access-audit/store"
)

// placeLegalHold puts a legal hold on a data subject, exempting its records from
// retention purge.
//
// @operationId PlaceLegalHold
// @title Place a legal hold
// @description Exempts a data subject's records from retention purge until cleared (e.g. an active investigation or dispute).
// @param LegalHold body request.LegalHold true "Subject + reason"
// @success 200 LegalHoldResponse response.LegalHold "Hold placed"
// @failure 400 string string "Invalid request"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource Governance
// @route /v1/legal-holds [post].
func (r *router) placeLegalHold(ctx *azugo.Context) {
	if !r.requireScope(ctx, "admin") {
		return
	}

	var req request.LegalHold
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	if err := r.Store().SetLegalHold(ctx, req.Subject, req.Reason, ctx.User().ID(), true); err != nil {
		ctx.Error(err)

		return
	}

	r.Events().LegalHoldChanged(ctx, req.Subject, true, ctx.User().ID())
	ctx.JSON(&response.LegalHold{Subject: req.Subject, Hold: true})
}

// clearLegalHold removes a legal hold from a data subject.
//
// @operationId ClearLegalHold
// @title Clear a legal hold
// @description Removes a legal hold; the subject's records become eligible for retention purge again.
// @param subject path string true "Pseudonymous internal data-subject reference"
// @success 200 LegalHoldResponse response.LegalHold "Hold cleared"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource Governance
// @route /v1/legal-holds/{subject} [delete].
func (r *router) clearLegalHold(ctx *azugo.Context) {
	if !r.requireScope(ctx, "admin") {
		return
	}

	subject := ctx.Params.String("subject")
	if subject == "" {
		ctx.Error(azugo.ParamRequiredError{Name: "subject"})

		return
	}

	if err := r.Store().SetLegalHold(ctx, subject, "", ctx.User().ID(), false); err != nil {
		ctx.Error(err)

		return
	}

	r.Events().LegalHoldChanged(ctx, subject, false, ctx.User().ID())
	ctx.JSON(&response.LegalHold{Subject: subject, Hold: false})
}

// purge triggers an immediate retention purge (periods older than the
// accountability window, skipping legal holds). Normally the background task
// runs this on a schedule; this is the manual/ops trigger.
//
// @operationId TriggerPurge
// @title Trigger retention purge
// @description Immediately purges records in periods older than the accountability window (legal holds skipped). The fact of purge is emitted as a security event.
// @success 200 PurgeResponse response.Purge "Purge result"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource Governance
// @route /v1/purge [post].
func (r *router) purge(ctx *azugo.Context) {
	if !r.requireScope(ctx, "admin") {
		return
	}

	cutoff := store.Period(time.Now().UTC().Add(-r.Config().RetentionWindow))

	res, err := r.Store().PurgeExpired(ctx, cutoff)
	if err != nil {
		ctx.Error(err)

		return
	}

	r.Events().RetentionPurge(res.Cutoff, res.Purged, res.RetainedUnderHold)
	ctx.JSON(&response.Purge{Cutoff: res.Cutoff, Purged: res.Purged, RetainedUnderHold: res.RetainedUnderHold})
}
