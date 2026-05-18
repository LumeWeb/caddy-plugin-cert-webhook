package certwebhook

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func init() {
	caddy.RegisterModule(&WebhookHandler{})
}

var _ caddyhttp.MiddlewareHandler = (*WebhookHandler)(nil)
