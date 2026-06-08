package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// GetFlowBySlug looks up a flow by its slug and returns it.
func (c *Client) GetFlowBySlug(ctx context.Context, slug string) (*Flow, error) {
	path := fmt.Sprintf("/api/v3/flows/instances/?slug=%s", url.QueryEscape(slug))

	var resp PaginatedResponse[Flow]
	if err := c.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("fetching flow %q: %w", slug, err)
	}

	if len(resp.Results) == 0 {
		return nil, fmt.Errorf("flow %q not found", slug)
	}

	return &resp.Results[0], nil
}
