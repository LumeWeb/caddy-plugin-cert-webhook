package certwebhook

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func init() {
	caddy.RegisterModule(CertWebhookApp{})
	httpcaddyfile.RegisterGlobalOption("cert_webhook", parseGlobalOption)
}

var _ caddy.App = (*CertWebhookApp)(nil)

func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next()
	return httpcaddyfile.App{
		Name:  "cert_webhook",
		Value: json.RawMessage(`{}`),
	}, nil
}
