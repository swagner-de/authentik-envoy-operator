package authentik

import (
	"context"
	"fmt"
	"net/http"
)

func (c *Client) CreatePolicyBinding(ctx context.Context, req PolicyBindingRequest) (*PolicyBinding, error) {
	var binding PolicyBinding
	if err := c.Do(ctx, http.MethodPost, "/api/v3/policies/bindings/", req, &binding); err != nil {
		return nil, fmt.Errorf("creating policy binding: %w", err)
	}
	return &binding, nil
}

func (c *Client) DeletePolicyBinding(ctx context.Context, id string) error {
	path := fmt.Sprintf("/api/v3/policies/bindings/%s/", id)
	if err := c.Do(ctx, http.MethodDelete, path, nil, nil); err != nil {
		return fmt.Errorf("deleting policy binding %q: %w", id, err)
	}
	return nil
}

func (c *Client) ListPolicyBindings(ctx context.Context, targetID string) ([]PolicyBinding, error) {
	path := fmt.Sprintf("/api/v3/policies/bindings/?target=%s", targetID)
	var resp PaginatedResponse[PolicyBinding]
	if err := c.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("listing policy bindings for target %q: %w", targetID, err)
	}
	return resp.Results, nil
}
