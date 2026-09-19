package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

func (c *Client) CreateApplication(ctx context.Context, req ApplicationRequest) (*Application, error) {
	var app Application
	if err := c.Do(ctx, http.MethodPost, "/api/v3/core/applications/", req, &app); err != nil {
		return nil, fmt.Errorf("creating application: %w", err)
	}
	return &app, nil
}

func (c *Client) UpdateApplication(ctx context.Context, slug string, req ApplicationRequest) (*Application, error) {
	path := fmt.Sprintf("/api/v3/core/applications/%s/", url.PathEscape(slug))
	var app Application
	if err := c.Do(ctx, http.MethodPut, path, req, &app); err != nil {
		return nil, fmt.Errorf("updating application %q: %w", slug, err)
	}
	return &app, nil
}

func (c *Client) GetApplication(ctx context.Context, slug string) (*Application, error) {
	path := fmt.Sprintf("/api/v3/core/applications/%s/", url.PathEscape(slug))
	var app Application
	if err := c.Do(ctx, http.MethodGet, path, nil, &app); err != nil {
		return nil, fmt.Errorf("getting application %q: %w", slug, err)
	}
	return &app, nil
}

func (c *Client) DeleteApplication(ctx context.Context, slug string) error {
	path := fmt.Sprintf("/api/v3/core/applications/%s/", url.PathEscape(slug))
	if err := c.Do(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("deleting application %q: %w", slug, err)
	}
	return nil
}
