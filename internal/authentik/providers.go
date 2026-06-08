package authentik

import (
	"context"
	"fmt"
	"net/http"
)

func (c *Client) CreateProvider(ctx context.Context, req OAuth2ProviderRequest) (*OAuth2Provider, error) {
	var provider OAuth2Provider
	if err := c.Do(ctx, http.MethodPost, "/api/v3/providers/oauth2/", req, &provider); err != nil {
		return nil, fmt.Errorf("creating provider: %w", err)
	}
	return &provider, nil
}

func (c *Client) UpdateProvider(ctx context.Context, id int, req OAuth2ProviderRequest) (*OAuth2Provider, error) {
	path := fmt.Sprintf("/api/v3/providers/oauth2/%d/", id)
	var provider OAuth2Provider
	if err := c.Do(ctx, http.MethodPut, path, req, &provider); err != nil {
		return nil, fmt.Errorf("updating provider %d: %w", id, err)
	}
	return &provider, nil
}

func (c *Client) GetProvider(ctx context.Context, id int) (*OAuth2Provider, error) {
	path := fmt.Sprintf("/api/v3/providers/oauth2/%d/", id)
	var provider OAuth2Provider
	if err := c.Do(ctx, http.MethodGet, path, nil, &provider); err != nil {
		return nil, fmt.Errorf("getting provider %d: %w", id, err)
	}
	return &provider, nil
}

func (c *Client) DeleteProvider(ctx context.Context, id int) error {
	path := fmt.Sprintf("/api/v3/providers/oauth2/%d/", id)
	if err := c.Do(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("deleting provider %d: %w", id, err)
	}
	return nil
}
