package authentik

import "testing"

func TestProviderNeedsUpdate_NoChange(t *testing.T) {
	current := &OAuth2Provider{
		PK:               1,
		Name:             "test-app",
		ClientID:         "client-id",
		ClientType:       "confidential",
		AuthorizationFlow: "flow-uuid-1",
		InvalidationFlow:  "flow-uuid-2",
		SigningKey:        "key-uuid",
		RedirectURIs: []RedirectURI{
			{MatchingMode: "strict", URL: "https://example.com/oauth2/callback", RedirectURIType: "authorization"},
		},
		PropertyMappings: []string{"uuid-1", "uuid-2"},
	}
	desired := OAuth2ProviderRequest{
		Name:              "test-app",
		ClientID:          "client-id",
		ClientType:        "confidential",
		AuthorizationFlow: "flow-uuid-1",
		InvalidationFlow:  "flow-uuid-2",
		SigningKey:         "key-uuid",
		RedirectURIs: []RedirectURI{
			{MatchingMode: "strict", URL: "https://example.com/oauth2/callback", RedirectURIType: "authorization"},
		},
		PropertyMappings: []string{"uuid-1", "uuid-2"},
	}

	if ProviderNeedsUpdate(current, desired) {
		t.Error("expected no update needed when state matches")
	}
}

func TestProviderNeedsUpdate_NameChanged(t *testing.T) {
	current := &OAuth2Provider{Name: "old-name", AuthorizationFlow: "f", InvalidationFlow: "f"}
	desired := OAuth2ProviderRequest{Name: "new-name", AuthorizationFlow: "f", InvalidationFlow: "f"}

	if !ProviderNeedsUpdate(current, desired) {
		t.Error("expected update needed when name differs")
	}
}

func TestProviderNeedsUpdate_RedirectURIsReordered(t *testing.T) {
	current := &OAuth2Provider{
		Name:              "app",
		AuthorizationFlow: "f",
		InvalidationFlow:  "f",
		RedirectURIs: []RedirectURI{
			{MatchingMode: "strict", URL: "https://a.com/cb", RedirectURIType: "authorization"},
			{MatchingMode: "strict", URL: "https://b.com/cb", RedirectURIType: "authorization"},
		},
	}
	desired := OAuth2ProviderRequest{
		Name:              "app",
		AuthorizationFlow: "f",
		InvalidationFlow:  "f",
		RedirectURIs: []RedirectURI{
			{MatchingMode: "strict", URL: "https://b.com/cb", RedirectURIType: "authorization"},
			{MatchingMode: "strict", URL: "https://a.com/cb", RedirectURIType: "authorization"},
		},
	}

	if ProviderNeedsUpdate(current, desired) {
		t.Error("expected no update needed when redirect URIs are just reordered")
	}
}

func TestProviderNeedsUpdate_PropertyMappingsReordered(t *testing.T) {
	current := &OAuth2Provider{
		Name:             "app",
		AuthorizationFlow: "f",
		InvalidationFlow:  "f",
		PropertyMappings: []string{"uuid-2", "uuid-1", "uuid-3"},
	}
	desired := OAuth2ProviderRequest{
		Name:              "app",
		AuthorizationFlow: "f",
		InvalidationFlow:  "f",
		PropertyMappings:  []string{"uuid-1", "uuid-2", "uuid-3"},
	}

	if ProviderNeedsUpdate(current, desired) {
		t.Error("expected no update needed when property mappings are just reordered")
	}
}

func TestProviderNeedsUpdate_SigningKeyChanged(t *testing.T) {
	current := &OAuth2Provider{Name: "app", AuthorizationFlow: "f", InvalidationFlow: "f", SigningKey: "old-key"}
	desired := OAuth2ProviderRequest{Name: "app", AuthorizationFlow: "f", InvalidationFlow: "f", SigningKey: "new-key"}

	if !ProviderNeedsUpdate(current, desired) {
		t.Error("expected update needed when signing key differs")
	}
}

func TestProviderNeedsUpdate_RedirectURIAdded(t *testing.T) {
	current := &OAuth2Provider{
		Name:              "app",
		AuthorizationFlow: "f",
		InvalidationFlow:  "f",
		RedirectURIs: []RedirectURI{
			{MatchingMode: "strict", URL: "https://a.com/cb", RedirectURIType: "authorization"},
		},
	}
	desired := OAuth2ProviderRequest{
		Name:              "app",
		AuthorizationFlow: "f",
		InvalidationFlow:  "f",
		RedirectURIs: []RedirectURI{
			{MatchingMode: "strict", URL: "https://a.com/cb", RedirectURIType: "authorization"},
			{MatchingMode: "strict", URL: "https://b.com/cb", RedirectURIType: "authorization"},
		},
	}

	if !ProviderNeedsUpdate(current, desired) {
		t.Error("expected update needed when redirect URI added")
	}
}

func TestApplicationNeedsUpdate_NoChange(t *testing.T) {
	current := &Application{
		PK:               "pk-1",
		Name:             "test-app",
		Slug:             "test-app",
		Provider:         42,
		PolicyEngineMode: "any",
	}
	desired := ApplicationRequest{
		Name:             "test-app",
		Slug:             "test-app",
		Provider:         42,
		PolicyEngineMode: "any",
	}

	if ApplicationNeedsUpdate(current, desired) {
		t.Error("expected no update needed when state matches")
	}
}

func TestApplicationNeedsUpdate_ProviderChanged(t *testing.T) {
	current := &Application{Name: "app", Slug: "app", Provider: 1, PolicyEngineMode: "any"}
	desired := ApplicationRequest{Name: "app", Slug: "app", Provider: 2, PolicyEngineMode: "any"}

	if !ApplicationNeedsUpdate(current, desired) {
		t.Error("expected update needed when provider differs")
	}
}

func TestApplicationNeedsUpdate_PolicyEngineModeChanged(t *testing.T) {
	current := &Application{Name: "app", Slug: "app", Provider: 1, PolicyEngineMode: "any"}
	desired := ApplicationRequest{Name: "app", Slug: "app", Provider: 1, PolicyEngineMode: "all"}

	if !ApplicationNeedsUpdate(current, desired) {
		t.Error("expected update needed when policy engine mode differs")
	}
}
