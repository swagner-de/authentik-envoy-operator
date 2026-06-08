package authentik

// RedirectURI represents a redirect URI entry.
type RedirectURI struct {
	MatchingMode    string `json:"matching_mode"`
	URL             string `json:"url"`
	RedirectURIType string `json:"redirect_uri_type"`
}

// OAuth2ProviderRequest is the request body for creating/updating an OAuth2 provider.
type OAuth2ProviderRequest struct {
	Name                   string        `json:"name"`
	AuthorizationFlow      string        `json:"authorization_flow"`
	InvalidationFlow       string        `json:"invalidation_flow"`
	ClientType             string        `json:"client_type,omitempty"`
	ClientID               string        `json:"client_id,omitempty"`
	ClientSecret           string        `json:"client_secret,omitempty"`
	RedirectURIs           []RedirectURI `json:"redirect_uris,omitempty"`
	GrantTypes             []string      `json:"grant_types,omitempty"`
	SubMode                string        `json:"sub_mode,omitempty"`
	IssuerMode             string        `json:"issuer_mode,omitempty"`
	IncludeClaimsInIDToken bool          `json:"include_claims_in_id_token,omitempty"`
	SigningKey              string        `json:"signing_key,omitempty"`
	PropertyMappings       []string      `json:"property_mappings,omitempty"`
}

// OAuth2Provider is the response from the OAuth2 provider API.
type OAuth2Provider struct {
	PK                      int           `json:"pk"`
	Name                    string        `json:"name"`
	ClientID                string        `json:"client_id"`
	ClientSecret            string        `json:"client_secret"`
	AuthorizationFlow       string        `json:"authorization_flow"`
	InvalidationFlow        string        `json:"invalidation_flow"`
	RedirectURIs            []RedirectURI `json:"redirect_uris"`
	AssignedApplicationSlug string        `json:"assigned_application_slug"`
}

// ApplicationRequest is the request body for creating/updating an application.
type ApplicationRequest struct {
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	Provider         int    `json:"provider,omitempty"`
	PolicyEngineMode string `json:"policy_engine_mode,omitempty"`
	MetaLaunchURL    string `json:"meta_launch_url,omitempty"`
}

// Application is the response from the application API.
type Application struct {
	PK       string `json:"pk"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Provider int    `json:"provider"`
}

// PolicyBindingRequest is the request body for creating a policy binding.
type PolicyBindingRequest struct {
	Target  string `json:"target"`
	Group   string `json:"group,omitempty"`
	Order   int    `json:"order"`
	Enabled bool   `json:"enabled"`
	Negate  bool   `json:"negate"`
}

// PolicyBinding is the response from the policy binding API.
type PolicyBinding struct {
	PK      string `json:"pk"`
	Target  string `json:"target"`
	Group   string `json:"group"`
	Order   int    `json:"order"`
	Enabled bool   `json:"enabled"`
}

// Flow represents an Authentik flow.
type Flow struct {
	PK          string `json:"pk"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Designation string `json:"designation"`
}

// Group represents an Authentik group.
type Group struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
}

// PaginatedResponse wraps paginated API responses.
type PaginatedResponse[T any] struct {
	Pagination struct {
		Count   int `json:"count"`
		Current int `json:"current"`
	} `json:"pagination"`
	Results []T `json:"results"`
}

// APIError represents an error response from Authentik.
type APIError struct {
	StatusCode int
	Detail     string              `json:"detail"`
	Errors     map[string][]string `json:"errors,omitempty"`
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return "authentik API error"
}
