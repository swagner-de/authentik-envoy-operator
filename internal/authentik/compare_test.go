package authentik

import "testing"

func TestProviderNeedsUpdate_NoChange(t *testing.T) {
	current := &OAuth2Provider{
		PK:                1,
		Name:              "test-app",
		ClientID:          "client-id",
		ClientType:        "confidential",
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
		SigningKey:        "key-uuid",
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
		Name:              "app",
		AuthorizationFlow: "f",
		InvalidationFlow:  "f",
		PropertyMappings:  []string{"uuid-2", "uuid-1", "uuid-3"},
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

// TestProviderNeedsUpdate_EmptyDesiredTuningIgnoresServerDefaults guards against
// the churn bug: when the user leaves sub_mode / validity durations unset, the
// request omits them and Authentik returns its own non-empty defaults. Comparing
// those against an empty desired value must NOT report a change (which would drive
// an endless UpdateProvider loop on every reconcile).
func TestProviderNeedsUpdate_EmptyDesiredTuningIgnoresServerDefaults(t *testing.T) {
	current := &OAuth2Provider{
		Name: "app", AuthorizationFlow: "af", InvalidationFlow: "if",
		ClientType: "confidential", ClientID: "app", SigningKey: "sk",
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		SubMode:                "hashed_user_id", // Authentik default
		IncludeClaimsInIDToken: true,
		AccessTokenValidity:    "minutes=5", // Authentik default
		RefreshTokenValidity:   "days=30",   // Authentik default
		AccessCodeValidity:     "minutes=1", // Authentik default
	}
	desired := OAuth2ProviderRequest{
		Name: "app", AuthorizationFlow: "af", InvalidationFlow: "if",
		ClientType: "confidential", ClientID: "app", SigningKey: "sk",
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		IncludeClaimsInIDToken: true,
		// SubMode / *Validity intentionally left empty (user didn't set them).
	}
	if ProviderNeedsUpdate(current, desired) {
		t.Fatal("expected no update when desired tuning fields are empty and only server defaults differ")
	}
}

func TestProviderNeedsUpdate_GrantTypesAndTuning(t *testing.T) {
	base := &OAuth2Provider{
		Name: "app", AuthorizationFlow: "af", InvalidationFlow: "if",
		ClientType: "confidential", ClientID: "app", SigningKey: "sk",
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		SubMode:                "hashed_user_id",
		IncludeClaimsInIDToken: true,
		AccessTokenValidity:    "minutes=10",
	}
	desired := OAuth2ProviderRequest{
		Name: "app", AuthorizationFlow: "af", InvalidationFlow: "if",
		ClientType: "confidential", ClientID: "app", SigningKey: "sk",
		GrantTypes:             []string{"refresh_token", "authorization_code"}, // order-insensitive
		SubMode:                "hashed_user_id",
		IncludeClaimsInIDToken: true,
		AccessTokenValidity:    "minutes=10",
	}
	if ProviderNeedsUpdate(base, desired) {
		t.Fatal("expected no update when only grant-type order differs")
	}
	desired.SubMode = "user_email"
	if !ProviderNeedsUpdate(base, desired) {
		t.Fatal("expected update when sub_mode changes")
	}
	desired.SubMode = "hashed_user_id"
	desired.AccessTokenValidity = "hours=1"
	if !ProviderNeedsUpdate(base, desired) {
		t.Fatal("expected update when access_token_validity changes")
	}
}

// TestApplicationNeedsUpdate_EmptyDesiredMetaIgnoresExternalValues guards the
// same churn bug as the provider tuning fields: meta_* and group are omitempty in
// ApplicationRequest, so when the CR omits appMeta the request never sends them.
// If an operator or user set those fields directly in Authentik, GET returns
// non-empty values that our empty desired can never overwrite (omitempty drops
// them from the PUT body). Reporting a change there drives an endless
// UpdateApplication loop that never converges.
func TestApplicationNeedsUpdate_EmptyDesiredMetaIgnoresExternalValues(t *testing.T) {
	current := &Application{
		Name: "matterhub", Slug: "smarthome-matterhub", Provider: 44,
		PolicyEngineMode: "any",
		MetaDescription:  "Matter/Smart-Home-Steuerzentrale",
		MetaIcon:         "https://cdn.example.com/matter.svg",
		Group:            "Leisure Apps",
	}
	desired := ApplicationRequest{
		Name: "matterhub", Slug: "smarthome-matterhub", Provider: 44,
		PolicyEngineMode: "any",
		// meta_* / group intentionally left empty (CR has no appMeta).
	}
	if ApplicationNeedsUpdate(current, desired) {
		t.Fatal("expected no update when desired meta fields are empty and only externally-set values differ")
	}
}

func TestApplicationNeedsUpdate_Meta(t *testing.T) {
	base := &Application{
		Name: "App", Slug: "app", Provider: 1, PolicyEngineMode: "any",
		MetaDescription: "d", Group: "g",
	}
	desired := ApplicationRequest{
		Name: "App", Slug: "app", Provider: 1, PolicyEngineMode: "any",
		MetaDescription: "d", Group: "g",
	}
	if ApplicationNeedsUpdate(base, desired) {
		t.Fatal("expected no update for identical meta")
	}
	desired.MetaDescription = "changed"
	if !ApplicationNeedsUpdate(base, desired) {
		t.Fatal("expected update when meta_description changes")
	}
}
