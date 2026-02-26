package certwebhook

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func init() {
	caddy.RegisterModule(&WebhookHandler{})
	httpcaddyfile.RegisterHandlerDirective("cert_webhook", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler WebhookHandler
	for h.Next() {
		switch h.Val() {
		case "portal_url":
			if !h.NextArg() {
				return &handler, h.ArgErr()
			}
			handler.PortalURL = h.Val()
		default:
			return nil, h.Errf("unrecognized subdirective '%s'", h.Val())
		}
	}

	return &handler, nil
}
