package main

import (
	"azugo.io/azugo/server"
	"azugo.io/core/cli"

	app "github.com/go-make-bytes/access-audit"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Access Audit Service",
		AppVer:        Version,
		Configuration: app.NewConfiguration(),
	}))
}
