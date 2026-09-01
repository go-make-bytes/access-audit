package routes

import (
	"encoding/json"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	api "github.com/go-make-bytes/access-audit"
	"github.com/go-make-bytes/access-audit/store"
)

// verifyTestApp returns the test app plus its in-memory store for assertions.
func verifyTestApp(t *testing.T) (*azugo.TestApp, *store.Memory) {
	t.Helper()

	app := api.TestApp(t)
	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	mem, ok := app.Store().(*store.Memory)
	qt.Assert(t, qt.IsTrue(ok))

	return azugo.NewTestApp(app.App), mem
}

func TestRecordVerifyEvent(t *testing.T) {
	app, mem := verifyTestApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.PostJSON("/v1/verify-events", map[string]any{
		"ts":            "2026-07-20T10:00:00Z",
		"ip":            "203.0.113.7",
		"userAgent":     "Mozilla/5.0",
		"sizeBytes":     12345,
		"sha256":        "ab12",
		"verdict":       "PASSED",
		"correlationId": "corr-1",
		"sessionId":     "sess-1",
	}, tc.WithHeader("X-Test-Scopes", "verify-audit:write"), tc.WithHeader("X-Test-Sub", "svc:portal-api"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out map[string]string
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	qt.Check(t, qt.Not(qt.Equals(out["eventId"], "")))

	evs := mem.VerifyEvents()
	qt.Assert(t, qt.Equals(len(evs), 1))
	qt.Check(t, qt.Equals(evs[0].Verdict, "PASSED"))
	qt.Check(t, qt.Equals(evs[0].IP, "203.0.113.7"))
	qt.Check(t, qt.Equals(evs[0].SessionID, "sess-1"))
	qt.Check(t, qt.Equals(evs[0].SourceService, "svc:portal-api"))
}

func TestRecordVerifyEventRequiresOwnScope(t *testing.T) {
	app, mem := verifyTestApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	// The GDPR access-record scope does NOT authorize the verify surface.
	resp, err := tc.PostJSON("/v1/verify-events", map[string]any{"verdict": "PASSED"},
		tc.WithHeader("X-Test-Scopes", "access-audit:write"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
	qt.Check(t, qt.Equals(len(mem.VerifyEvents()), 0))
}

func TestRecordVerifyEventVerdictRequired(t *testing.T) {
	app, _ := verifyTestApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.PostJSON("/v1/verify-events", map[string]any{"ip": "203.0.113.7"},
		tc.WithHeader("X-Test-Scopes", "verify-audit:write"))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}
