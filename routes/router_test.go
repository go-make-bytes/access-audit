package routes

import (
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"

	api "github.com/go-make-bytes/access-audit"
)

func testApp(t testing.TB) *azugo.TestApp {
	app := api.TestApp(t)

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}
