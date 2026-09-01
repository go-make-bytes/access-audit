package routes

import (
	"time"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"
	"github.com/valyala/fasthttp"

	"github.com/go-make-bytes/access-audit/store"
)

// verifyEventRequest is one abuse-evidence event from a public-verification
// front end. All caller-descriptive fields are optional — an event with only a
// verdict still records that the anonymous surface was driven.
type verifyEventRequest struct {
	TS            string `json:"ts"`
	IP            string `json:"ip"`
	UserAgent     string `json:"userAgent"`
	SizeBytes     int64  `json:"sizeBytes"`
	SHA256        string `json:"sha256"`
	Verdict       string `json:"verdict"`
	CorrelationID string `json:"correlationId"`
	SessionID     string `json:"sessionId"`
}

// recordVerifyEvent persists one verify abuse-evidence event — the
// purpose-scoped second surface of this service (its own schema, lawful basis
// and retention; separate from the GDPR access log). The calling service is
// taken from the authenticated identity, never the body.
//
// @operationId RecordVerifyEvent
// @title Record a public-verification evidence event
// @description Persists one abuse-evidence event for the anonymous document-verification surface: request metadata + the upload's hash, never document content. Swept after the configured retention window.
// @param VerifyEvent body verifyEventRequest true "The evidence event"
// @success 201 {empty} "Recorded"
// @failure 400 string string "Invalid event"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource VerifyEvents
// @route /v1/verify-events [post].
func (r *router) recordVerifyEvent(ctx *azugo.Context) {
	// Its own scope group: the verify-evidence grant is separable from the
	// GDPR access-record one.
	if !ctx.User().HasScopeLevel("verify-audit", "write") {
		r.Events().AuthzDenied(ctx, "verify-audit:write", ctx.User().ID(), ctx.Path())
		ctx.Error(corehttp.ForbiddenError{})

		return
	}

	var req verifyEventRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}
	if req.Verdict == "" {
		ctx.Error(azugo.ParamRequiredError{Name: "verdict"})

		return
	}

	ts := time.Now().UTC()
	if req.TS != "" {
		t, err := time.Parse(time.RFC3339, req.TS)
		if err != nil {
			ctx.Error(azugo.ParamInvalidError{Name: "ts", Tag: "rfc3339", Err: err})

			return
		}
		ts = t
	}

	id, err := r.Store().AppendVerifyEvent(ctx, &store.VerifyEvent{
		TS:            ts,
		IP:            req.IP,
		UserAgent:     req.UserAgent,
		SizeBytes:     req.SizeBytes,
		SHA256:        req.SHA256,
		Verdict:       req.Verdict,
		CorrelationID: req.CorrelationID,
		SessionID:     req.SessionID,
		SourceService: ctx.User().ID(), // derived from the authenticated identity
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(map[string]string{"eventId": id})
}
