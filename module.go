package certwebhook

import (
	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func init() {
	caddy.RegisterModule(CertWebhookApp{})
}

var _ caddy.App = (*CertWebhookApp)(nil)
