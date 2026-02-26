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
- Async webhook delivery with exponential backoff retry for transient failures
- Non-blocking delivery to avoid disrupting certificate operations

## Installation

Build Caddy with this plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/LumeWeb/caddy-plugin-cert-webhook
```

## Quick Start

```caddyfile
{
    order cert_webhook before file_server
}

example.com {
    tls {
        cert_webhook {
            portal_url https://portal.example.com
        }
    }
}
```

Set environment variables:

```bash
export PORTAL_URL=https://portal.example.com
export GATEWAY_SECRET=your-secure-secret-key

caddy run --config Caddyfile
```

## Configuration

### Caddyfile

```caddyfile
tls {
    cert_webhook {
        portal_url https://portal.example.com
        timeout 30s
        retry_count 5
    }
}
```

### JSON

```json
{
    "http.handlers": {
        "cert_webhook": {
            "portal_url": "https://portal.example.com",
            "timeout": "30s",
            "retry_count": 5
        }
    }
}
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORTAL_URL` | Yes | Base URL of the portal service |
| `GATEWAY_SECRET` | Yes | Shared secret for authentication |

## Webhook Format

The plugin sends POST requests to `/internal/websites/:domain/ssl-status`:

**Headers:**
```
Content-Type: application/json
X-Gateway-Secret: <configured_secret>
```

**Body:**
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

- **Transient errors** (5xx, network timeouts): Retried with exponential backoff (5 attempts max)
- **Permanent errors** (4xx): Logged but not retried
- Webhook delivery failures do not block certificate operations

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
