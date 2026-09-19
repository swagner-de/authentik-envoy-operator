package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// GetFlowBySlug looks up a flow by its slug and returns it. Returns (nil, nil)
// when no flow matches, so callers can distinguish absence from an API error.
func (c *Client) GetFlowBySlug(ctx context.Context, slug string) (*Flow, error) {
	path := fmt.Sprintf("/api/v3/flows/instances/?slug=%s", url.QueryEscape(slug))

	var resp PaginatedResponse[Flow]
	if err := c.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("fetching flow %q: %w", slug, err)
	}

	for i := range resp.Results {
		if resp.Results[i].Slug == slug {
			return &resp.Results[i], nil
		}
	}
	return nil, nil
}
