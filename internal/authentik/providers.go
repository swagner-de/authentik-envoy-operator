package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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

// GetProviderByName looks up an OAuth2 provider by exact name.
// Returns (nil, nil) when no provider matches (used for orphan recovery).
func (c *Client) GetProviderByName(ctx context.Context, name string) (*OAuth2Provider, error) {
	path := fmt.Sprintf("/api/v3/providers/oauth2/?name=%s", url.QueryEscape(name))
	var resp PaginatedResponse[OAuth2Provider]
	if err := c.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("listing providers by name %q: %w", name, err)
	}
	for i := range resp.Results {
		if resp.Results[i].Name == name {
			return &resp.Results[i], nil
		}
	}
	return nil, nil
}
