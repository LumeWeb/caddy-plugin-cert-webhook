# Caddy Certificate Event Webhooks

[![Go Version](https://img.shields.io/badge/Go-1.26-blue.svg)](https://go.dev/dl/go1.26)
[![Caddy Version](https://img.shields.io/badge/Caddy-v2.11.1-orange.svg)](https://caddyserver.com/docs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/github/actions/workflow/status/LumeWeb/caddy-plugin-cert-webhook/test.yml?branch=main&label=Tests)](https://github.com/LumeWeb/caddy-plugin-cert-webhook/actions)

A Caddy v2 plugin that hooks into certificate lifecycle events and sends webhooks to a central portal service for real-time SSL certificate status tracking.

## Features

- Subscribes to Caddy TLS certificate events (`cert_obtained`, `cert_renewed`, `cert_expired`)
- Sends webhooks to portal endpoint with `X-Gateway-Secret` authentication
- Maps Caddy events to portal SSL statuses (`pending`, `issuing`, `ready`, `failed`)
- Async webhook delivery with concurrency limiting
- Non-blocking delivery to avoid disrupting certificate operations
- Debug logging via Caddy's `{ debug }` global option

## Installation

Build Caddy with this plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/LumeWeb/caddy-plugin-cert-webhook
```

## Configuration

All configuration is via environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `PORTAL_URL` | Yes | Base URL of the portal service |
| `GATEWAY_SECRET` | Yes | Shared secret for authentication |

### JSON Config

Register the handler in your route:

```json
{
    "apps": {
        "http": {
            "servers": {
                "srv0": {
                    "routes": [
                        {
                            "handle": [{
                                "handler": "cert_webhook"
                            }]
                        }
                    ]
                }
            }
        }
    }
}
```

### Debug Logging

Add `{ debug }` to your Caddyfile or set the log level in JSON config to see detailed operational logs:

```caddyfile
{
    debug
}
```

This enables debug-level output including event data, webhook delivery details, and config resolution.

## Webhook Format

The plugin calls the portal SDK's `UpdateSSLStatusInternal` method with:

```json
{
    "status": "ready",
    "error": "",
    "timestamp": "2026-02-26T01:00:00Z"
}
```

## Status Mapping

| Caddy Event | Portal Status |
|-------------|---------------|
| `cert_obtained` | `ready` (or `failed` if error) |
| `cert_renewed` | `ready` (or `failed` if error) |
| `cert_expired` | `failed` |

## Error Handling

- Webhook delivery failures are logged but do not block certificate operations
- Delivery uses a concurrency-limited worker pool (100 concurrent max)

## Development

```bash
# Build Caddy with plugin
xcaddy build --with github.com/LumeWeb/caddy-plugin-cert-webhook

# Run tests
go test ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Run linters
go vet ./...

# Format code
go fmt ./...

# Download dependencies
go mod download
go mod tidy
```

## License

MIT License - see [LICENSE](LICENSE) for details.
