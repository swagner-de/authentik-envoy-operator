package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// GetGroupByName looks up a group by name and returns it.
func (c *Client) GetGroupByName(ctx context.Context, name string) (*Group, error) {
	path := fmt.Sprintf("/api/v3/core/groups/?name=%s", url.QueryEscape(name))

	var resp PaginatedResponse[Group]
	if err := c.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("fetching group %q: %w", name, err)
	}

	if len(resp.Results) == 0 {
		return nil, fmt.Errorf("group %q not found", name)
	}

	return &resp.Results[0], nil
}
