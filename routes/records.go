package routes

import (
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	"github.com/go-make-bytes/access-audit/routes/request"
	"github.com/go-make-bytes/access-audit/routes/response"
	"github.com/go-make-bytes/access-audit/store"
)

// recordAccess persists one GDPR personal-data access record. The body is the
// access-record envelope a go-gdpr-audit producer posts; the service seals it and
// appends it (idempotent on event_id, so an outbox retry returns 200 with
// duplicate=true rather than creating a second row).
//
// @operationId RecordAccess
// @title Record a personal-data access
// @description Persists a gdpr_access envelope into the append-only, subject-indexed log. Idempotent on event_id. The calling system/source is taken from the authenticated identity, never the body.
// @param AccessRecord body request.AccessRecord true "The access-record envelope"
// @success 201 RecordedResponse response.Recorded "Recorded"
// @success 200 RecordedResponse response.Recorded "Already recorded (duplicate event_id)"
// @failure 400 string string "Invalid record"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource AccessRecords
// @route /v1/access-records [post].
func (r *router) recordAccess(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}

	var req request.AccessRecord
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)

		return
	}

	env := req.Envelope
	request.Sanitize(&env)

	sealHex, err := r.Sealer().Seal(&env)
	if err != nil {
		ctx.Error(err)

		return
	}

	res, err := r.Store().Append(ctx, &store.Record{
		Envelope:      env,
		Seal:          sealHex,
		SourceService: ctx.User().ID(), // derived from the authenticated identity
		System:        r.Config().System,
	})
	if err != nil {
		ctx.Error(err)

		return
	}

	if !res.Duplicate {
		ctx.StatusCode(fasthttp.StatusCreated)
	}
	ctx.JSON(&response.Recorded{RecordID: res.RecordID, EventID: res.EventID, Duplicate: res.Duplicate})
}

// subjectRecords answers a DSAR: every access record concerning a data subject.
// Each record's stored seal is re-verified and reported.
//
// @operationId SubjectAccessRecords
// @title Access records for a data subject (DSAR)
// @description Every recorded access to a data subject's personal data (Art. 15), each with an integrity check of its stored seal. Optional from/to (RFC3339) and limit.
// @param subject path string true "Pseudonymous internal data-subject reference"
// @param from query string false "Lower bound on occurred_at (RFC3339)"
// @param to query string false "Upper bound on occurred_at (RFC3339)"
// @param limit query int false "Max records (default 1000, max 10000)"
// @success 200 SubjectRecordsResponse response.SubjectRecords "Records"
// @failure 400 string string "Invalid query"
// @failure 401 {empty} "Unauthorized"
// @failure 403 {empty} "Forbidden"
// @resource AccessRecords
// @route /v1/subjects/{subject}/access-records [get].
func (r *router) subjectRecords(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}

	subject := ctx.Params.String("subject")
	if subject == "" {
		ctx.Error(azugo.ParamRequiredError{Name: "subject"})

		return
	}

	from, to, ok := r.timeRange(ctx)
	if !ok {
		return
	}

	limit := 0
	l, err := ctx.Query.IntOptional("limit")
	if err != nil {
		ctx.Error(azugo.ParamInvalidError{Name: "limit", Tag: "numeric", Err: err})

		return
	}
	if l != nil {
		limit = *l
	}

	recs, err := r.Store().BySubject(ctx, subject, from, to, limit)
	if err != nil {
		ctx.Error(err)

		return
	}

	out := response.SubjectRecords{Subject: subject, Count: len(recs)}
	for _, rec := range recs {
		integrity := "ok"
		if !r.Sealer().Verify(&rec.Envelope, rec.Seal) {
			integrity = "failed"
			r.Events().IntegrityMismatch(ctx, "subject:"+subject, "seal mismatch for record "+rec.Envelope.EventID)
		}
		out.Records = append(out.Records, response.SubjectRecord{Envelope: rec.Envelope, Integrity: integrity})
	}

	ctx.JSON(&out)
}

// timeRange parses optional ?from= / ?to= RFC3339 query parameters.
func (r *router) timeRange(ctx *azugo.Context) (from, to time.Time, ok bool) {
	if v := ctx.Query.StringOptional("from"); v != nil && *v != "" {
		t, err := time.Parse(time.RFC3339, *v)
		if err != nil {
			ctx.Error(azugo.ParamInvalidError{Name: "from", Tag: "rfc3339", Err: err})

			return time.Time{}, time.Time{}, false
		}
		from = t
	}
	if v := ctx.Query.StringOptional("to"); v != nil && *v != "" {
		t, err := time.Parse(time.RFC3339, *v)
		if err != nil {
			ctx.Error(azugo.ParamInvalidError{Name: "to", Tag: "rfc3339", Err: err})

			return time.Time{}, time.Time{}, false
		}
		to = t
	}

	return from, to, true
}
