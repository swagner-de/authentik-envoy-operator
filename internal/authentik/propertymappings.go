package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// ScopeMapping represents an Authentik OAuth2 scope mapping.
type ScopeMapping struct {
	PK        string `json:"pk"`
	Name      string `json:"name"`
	ScopeName string `json:"scope_name"`
}

// GetScopeMappingByName looks up a scope mapping by its name. Returns (nil, nil)
// when no mapping matches, so callers can distinguish absence from an API error.
func (c *Client) GetScopeMappingByName(ctx context.Context, name string) (*ScopeMapping, error) {
	path := fmt.Sprintf("/api/v3/propertymappings/provider/scope/?name=%s", url.QueryEscape(name))

	var resp PaginatedResponse[ScopeMapping]
	if err := c.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("fetching scope mapping %q: %w", name, err)
	}

	for i := range resp.Results {
		if resp.Results[i].Name == name {
			return &resp.Results[i], nil
		}
	}
	return nil, nil
}
