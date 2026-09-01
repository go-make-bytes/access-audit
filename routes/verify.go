package routes

import (
	"time"

	"azugo.io/azugo"
	corehttp "azugo.io/core/http"

	"github.com/go-make-bytes/access-audit/routes/response"
)

// verify checks log integrity. With ?subject= it re-verifies every stored seal
// for that subject; with ?period=YYYY-MM[-DD] it recomputes the period
// checkpoint from the current rows and compares it to the sealed checkpoint
// (detecting any row added/removed since the checkpoint).
//
// @operationId VerifyIntegrity
// @title Verify access-log integrity
// @description Re-verifies seals for a subject (?subject=) or recomputes and compares a period checkpoint (?period=YYYY-MM). A mismatch is reported and raises a security event.
// @param subject query string false "Verify all records for this data-subject ref"
// @param period query string false "Verify this retention period's checkpoint (YYYY-MM or YYYY-MM-DD)"
// @success 200 VerifyResponse response.Verify "Verification result"
// @failure 400 string string "Provide ?subject= or ?period="
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @failure 404 string string "No checkpoint for the period"
// @resource Integrity
// @route /v1/verify [get].
func (r *router) verify(ctx *azugo.Context) {
	if !r.requireScope(ctx, "admin") {
		return
	}

	if v := ctx.Query.StringOptional("subject"); v != nil && *v != "" {
		r.verifySubject(ctx, *v)

		return
	}
	if v := ctx.Query.StringOptional("period"); v != nil && *v != "" {
		r.verifyPeriod(ctx, *v)

		return
	}

	ctx.Error(azugo.BadRequestError{Description: "one of ?subject= or ?period= is required"})
}

func (r *router) verifySubject(ctx *azugo.Context, subject string) {
	recs, err := r.Store().BySubject(ctx, subject, time.Time{}, time.Time{}, 10000)
	if err != nil {
		ctx.Error(err)

		return
	}

	out := response.Verify{Scope: "subject", Target: subject, Checked: len(recs), OK: true}
	for _, rec := range recs {
		if !r.Sealer().Verify(&rec.Envelope, rec.Seal) {
			out.OK = false
			out.Mismatches = append(out.Mismatches, rec.Envelope.EventID)
		}
	}

	if !out.OK {
		r.Events().IntegrityMismatch(ctx, "subject:"+subject, "one or more seals failed")
	}
	ctx.JSON(&out)
}

func (r *router) verifyPeriod(ctx *azugo.Context, period string) {
	p, err := normalizePeriod(period)
	if err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "period", Tag: "yyyy-mm", Err: err})

		return
	}

	cp, err := r.Store().LoadCheckpoint(ctx, p)
	if err != nil {
		ctx.Error(err)

		return
	}
	if cp == nil {
		ctx.Error(corehttp.NotFoundError{Resource: "checkpoint"})

		return
	}

	seals, count, err := r.Store().SealsForPeriod(ctx, p)
	if err != nil {
		ctx.Error(err)

		return
	}

	out := response.Verify{
		Scope:   "period",
		Target:  p,
		Checked: count,
		OK:      r.Sealer().VerifyCheckpoint(seals, count, cp.Seal),
	}
	if !out.OK {
		out.Mismatches = append(out.Mismatches, p)
		r.Events().IntegrityMismatch(ctx, "period:"+p, "checkpoint mismatch — rows added or removed since sealing")
	}
	ctx.JSON(&out)
}

// normalizePeriod accepts "YYYY-MM" or "YYYY-MM-DD" and returns the first-of-
// month YYYY-MM-DD bucket the store uses.
func normalizePeriod(s string) (string, error) {
	if len(s) == 7 { // YYYY-MM
		s += "-01"
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return "", err
	}
	y, m, _ := t.UTC().Date()

	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02"), nil
}
