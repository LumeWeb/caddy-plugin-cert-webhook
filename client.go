package certwebhook

import (
	"fmt"
	"net/url"

	ipfs "go.lumeweb.com/ipfs-sdk"
)

type PortalClient struct {
	client   *ipfs.Client
	websites ipfs.WebsitesService
}

func NewPortalClient(portalURL, gatewaySecret string) (*PortalClient, error) {
	u, err := url.Parse(portalURL)
	if err != nil {
		return nil, fmt.Errorf("invalid portal URL: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	client, err := ipfs.NewClient(
		u.String(),
		"",
		ipfs.WithGatewaySecret(gatewaySecret),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create portal client: %w", err)
	}

	return &PortalClient{
		client:   client,
		websites: client.Websites(),
	}, nil
}

func (c *PortalClient) Websites() ipfs.WebsitesService {
	return c.websites
}

func (c *PortalClient) Close() {
	c.client = nil
	c.websites = nil
}
