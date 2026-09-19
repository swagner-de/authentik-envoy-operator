package authentik

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// CertificateKeyPair represents an Authentik certificate keypair.
type CertificateKeyPair struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
}

// GetCertificateKeyPairByName looks up a certificate keypair by name. Returns
// (nil, nil) when no keypair matches, so callers can distinguish absence from an
// API error.
func (c *Client) GetCertificateKeyPairByName(ctx context.Context, name string) (*CertificateKeyPair, error) {
	path := fmt.Sprintf("/api/v3/crypto/certificatekeypairs/?has_key=true&name=%s", url.QueryEscape(name))

	var resp PaginatedResponse[CertificateKeyPair]
	if err := c.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("fetching certificate keypair %q: %w", name, err)
	}

	for i := range resp.Results {
		if resp.Results[i].Name == name {
			return &resp.Results[i], nil
		}
	}
	return nil, nil
}
