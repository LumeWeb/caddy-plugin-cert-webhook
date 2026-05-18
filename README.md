# Caddy Certificate Event Webhooks

[![Go Version](https://img.shields.io/badge/Go-1.26-blue.svg)](https://go.dev/dl/go1.26)
[![Caddy Version](https://img.shields.io/badge/Caddy-v2.11.1-orange.svg)](https://caddyserver.com/docs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/github/actions/workflow/status/LumeWeb/caddy-plugin-cert-webhook/test.yml?branch=main&label=Tests)](https://github.com/LumeWeb/caddy-plugin-cert-webhook/actions)

A Caddy v2 app that hooks into certificate lifecycle events and reports SSL status to a portal service.

## Features

- Subscribes to Caddy TLS events (`cert_obtained`, `cert_renewed`, `cert_expired`)
- Reports status to portal via SDK (`ready` or `failed`)
- Async delivery with concurrency limiting (100 concurrent)
- Debug logging via Caddy's `{ debug }` global option

## Installation

```bash
xcaddy build --with github.com/LumeWeb/caddy-plugin-cert-webhook
```

## Configuration

Env vars only — no Caddyfile directives, no JSON fields:

| Variable | Required | Description |
|----------|----------|-------------|
| `PORTAL_URL` | Yes | Base URL of the portal service |
| `GATEWAY_SECRET` | Yes | Shared secret for authentication |

Enable the app in your Caddy JSON config:

```json
{
    "apps": {
        "cert_webhook": {}
    }
}
```

### Debug Logging

```caddyfile
{
    debug
}
```

Enables debug output for event data, webhook delivery, and config resolution.

## Status Mapping

| Caddy Event | Portal Status |
|-------------|---------------|
| `cert_obtained` | `ready` (or `failed` if error) |
| `cert_renewed` | `ready` (or `failed` if error) |
| `cert_expired` | `failed` |

## Error Handling

- Webhook delivery failures are logged but do not block certificate operations

## Development

```bash
go test ./...
go vet ./...
go fmt ./...
```
