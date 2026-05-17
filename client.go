package certwebhook

import (
	"fmt"

	ipfs "go.lumeweb.com/ipfs-sdk"
)

type PortalClient struct {
	client    *ipfs.Client
	websites  ipfs.WebsitesService
}

func NewPortalClient(portalURL, gatewaySecret string) (*PortalClient, error) {
	client, err := ipfs.NewClient(
		"https://"+portalURL,
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
