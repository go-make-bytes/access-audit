package routes

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

// healthz is the liveness probe.
func (r *router) healthz(ctx *azugo.Context) {
	ctx.SkipRequestLog()
	ctx.Text("ok")
}

// readyz reports readiness: the access-log store is reachable.
func (r *router) readyz(ctx *azugo.Context) {
	ctx.SkipRequestLog()

	if err := r.Store().Ping(ctx); err != nil {
		ctx.StatusCode(fasthttp.StatusServiceUnavailable)
		ctx.Text("store unavailable")

		return
	}

	ctx.Text("ready")
}
