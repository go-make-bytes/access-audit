package routes

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/gmb-lib/go-platform-kit/broker"

	"github.com/go-make-bytes/access-audit/routes/response"
)

const (
	scopeWrite = "access-audit:write"
	scopeRead  = "access-audit:read"
	scopeAdmin = "access-audit:admin"
)

func validEnvelope(eid, subject string) broker.Envelope {
	return broker.Envelope{
		EventID:      eid,
		OccurredAt:   time.Now().UTC(),
		Categories:   []broker.Category{broker.CategoryGDPRAccess},
		EventType:    "document.access",
		Operation:    broker.OpRead,
		LawfulBasis:  "contract",
		Purpose:      "signing",
		Outcome:      broker.OutcomeSuccess,
		DataSubjects: []string{subject},
	}
}

func decodeBody(t *testing.T, resp *fasthttp.Response, v any) {
	t.Helper()

	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	err = json.Unmarshal(buf, v)
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
}

func TestRecordAccessCreatedThenIdempotent(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	ev := validEnvelope("evt-1", "subj-1")

	resp, err := tc.PostJSON("/v1/access-records", &ev, tc.WithHeader("X-Test-Scopes", scopeWrite))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var first response.Recorded
	decodeBody(t, resp, &first)
	qt.Check(t, qt.IsFalse(first.Duplicate))

	// Outbox retry: same event_id → 200, duplicate, same record id.
	resp2, err := tc.PostJSON("/v1/access-records", &ev, tc.WithHeader("X-Test-Scopes", scopeWrite))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp2.StatusCode(), fasthttp.StatusOK))

	var second response.Recorded
	decodeBody(t, resp2, &second)
	qt.Check(t, qt.IsTrue(second.Duplicate))
	qt.Check(t, qt.Equals(second.RecordID, first.RecordID))
}

func TestRecordAccessUnauthorized(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	ev := validEnvelope("evt-2", "subj-1")

	resp, err := tc.PostJSON("/v1/access-records", &ev)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

func TestRecordAccessWrongScope(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	ev := validEnvelope("evt-3", "subj-1")

	resp, err := tc.PostJSON("/v1/access-records", &ev, tc.WithHeader("X-Test-Scopes", scopeRead))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	fasthttp.ReleaseResponse(resp)
}

func TestRecordAccessRejectsNonGDPR(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	ev := validEnvelope("evt-4", "subj-1")
	ev.Categories = []broker.Category{broker.CategorySigning} // not gdpr_access

	resp, err := tc.PostJSON("/v1/access-records", &ev, tc.WithHeader("X-Test-Scopes", scopeWrite))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)
}

func TestRecordAccessRejectsIdentifyingSubject(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	ev := validEnvelope("evt-5", "person@example.com") // an e-mail is not a pseudonymous ref

	resp, err := tc.PostJSON("/v1/access-records", &ev, tc.WithHeader("X-Test-Scopes", scopeWrite))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
}

func TestSubjectRecordsDSAR(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	ev := validEnvelope("evt-6", "subj-dsar")
	post, err := tc.PostJSON("/v1/access-records", &ev, tc.WithHeader("X-Test-Scopes", scopeWrite))
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(post)

	resp, err := tc.Get("/v1/subjects/subj-dsar/access-records", tc.WithHeader("X-Test-Scopes", scopeRead))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var out response.SubjectRecords
	decodeBody(t, resp, &out)
	qt.Check(t, qt.Equals(out.Count, 1))
	qt.Check(t, qt.Equals(out.Records[0].Integrity, "ok"))
	qt.Check(t, qt.Equals(out.Records[0].EventID, "evt-6"))
}

func TestVerifySubject(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	ev := validEnvelope("evt-7", "subj-verify")
	post, err := tc.PostJSON("/v1/access-records", &ev, tc.WithHeader("X-Test-Scopes", scopeWrite))
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(post)

	resp, err := tc.Get("/v1/verify",
		tc.WithHeader("X-Test-Scopes", scopeAdmin),
		tc.WithQuery(map[string]any{"subject": "subj-verify"}))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))

	var out response.Verify
	decodeBody(t, resp, &out)
	qt.Check(t, qt.Equals(out.Scope, "subject"))
	qt.Check(t, qt.Equals(out.Checked, 1))
	qt.Check(t, qt.IsTrue(out.OK))
}
