package authentik

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// DiscoveryDocument is the subset of the OIDC discovery document we surface.
type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// GetDiscoveryDocument fetches <issuer>.well-known/openid-configuration.
// issuer is expected to end with "/".
func (c *Client) GetDiscoveryDocument(ctx context.Context, issuer string) (*DiscoveryDocument, error) {
	base := strings.TrimPrefix(issuer, c.baseURL)
	path := strings.TrimRight(base, "/") + "/.well-known/openid-configuration"
	var doc DiscoveryDocument
	if err := c.Do(ctx, http.MethodGet, path, nil, &doc); err != nil {
		return nil, fmt.Errorf("fetching discovery document: %w", err)
	}
	return &doc, nil
}
