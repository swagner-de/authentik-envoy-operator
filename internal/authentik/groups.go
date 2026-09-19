package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// GetGroupByName looks up a group by exact name. Returns (nil, nil) when no
// group matches, so callers can distinguish a genuine absence from a transport
// or API error (which is returned as a non-nil error).
func (c *Client) GetGroupByName(ctx context.Context, name string) (*Group, error) {
	path := fmt.Sprintf("/api/v3/core/groups/?name=%s", url.QueryEscape(name))

	var resp PaginatedResponse[Group]
	if err := c.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("fetching group %q: %w", name, err)
	}
	for i := range resp.Results {
		if resp.Results[i].Name == name {
			return &resp.Results[i], nil
		}
	}
	return nil, nil
}

// DeleteGroup deletes a group by its primary key.
func (c *Client) DeleteGroup(ctx context.Context, pk string) error {
	path := fmt.Sprintf("/api/v3/core/groups/%s/", pk)
	if err := c.Do(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("deleting group %q: %w", pk, err)
	}
	return nil
}

// CreateGroup creates a group with the given name.
func (c *Client) CreateGroup(ctx context.Context, name string) (*Group, error) {
	var group Group
	body := map[string]string{"name": name}
	if err := c.Do(ctx, http.MethodPost, "/api/v3/core/groups/", body, &group); err != nil {
		return nil, fmt.Errorf("creating group %q: %w", name, err)
	}
	return &group, nil
}
