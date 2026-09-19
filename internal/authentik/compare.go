package authentik

import "slices"

// ProviderNeedsUpdate returns true if the current provider state in Authentik
// differs from the desired state described by the request.
func ProviderNeedsUpdate(current *OAuth2Provider, desired OAuth2ProviderRequest) bool {
	if current.Name != desired.Name {
		return true
	}
	if current.AuthorizationFlow != desired.AuthorizationFlow {
		return true
	}
	if current.InvalidationFlow != desired.InvalidationFlow {
		return true
	}
	if current.ClientType != desired.ClientType {
		return true
	}
	if current.ClientID != desired.ClientID {
		return true
	}
	if current.SigningKey != desired.SigningKey {
		return true
	}
	if !redirectURIsEqual(current.RedirectURIs, desired.RedirectURIs) {
		return true
	}
	if !StringSetEqual(current.PropertyMappings, desired.PropertyMappings) {
		return true
	}
	if !StringSetEqual(current.GrantTypes, desired.GrantTypes) {
		return true
	}
	if current.IncludeClaimsInIDToken != desired.IncludeClaimsInIDToken {
		return true
	}
	// SubMode and the validity durations are optional passthroughs (omitempty on
	// the request). When left unset by the user we don't send them, so Authentik
	// fills in its own server-side defaults (e.g. sub_mode="hashed_user_id",
	// access_token_validity="minutes=5"). Diffing an empty desired value against
	// that non-empty default would report a change on every reconcile and drive
	// an endless UpdateProvider loop, so only compare these when a value is set.
	if desired.SubMode != "" && current.SubMode != desired.SubMode {
		return true
	}
	if desired.AccessTokenValidity != "" && current.AccessTokenValidity != desired.AccessTokenValidity {
		return true
	}
	if desired.RefreshTokenValidity != "" && current.RefreshTokenValidity != desired.RefreshTokenValidity {
		return true
	}
	if desired.AccessCodeValidity != "" && current.AccessCodeValidity != desired.AccessCodeValidity {
		return true
	}
	return false
}

// ApplicationNeedsUpdate returns true if the current application state in Authentik
// differs from the desired state described by the request.
func ApplicationNeedsUpdate(current *Application, desired ApplicationRequest) bool {
	if current.Name != desired.Name {
		return true
	}
	if current.Slug != desired.Slug {
		return true
	}
	if current.Provider != desired.Provider {
		return true
	}
	if current.PolicyEngineMode != desired.PolicyEngineMode {
		return true
	}
	// meta_* and group carry omitempty on the request, so an unset (empty) desired
	// value is dropped from the PUT body and can never overwrite whatever Authentik
	// holds. When a value was set directly in Authentik (e.g. via the UI) but the CR
	// leaves appMeta unset, diffing that non-empty current against an empty desired
	// would report a change forever and drive an endless UpdateApplication loop that
	// never converges. Only compare these when the user actually set a value.
	if desired.MetaLaunchURL != "" && current.MetaLaunchURL != desired.MetaLaunchURL {
		return true
	}
	if desired.MetaDescription != "" && current.MetaDescription != desired.MetaDescription {
		return true
	}
	if desired.MetaPublisher != "" && current.MetaPublisher != desired.MetaPublisher {
		return true
	}
	if desired.MetaIcon != "" && current.MetaIcon != desired.MetaIcon {
		return true
	}
	if current.OpenInNewTab != desired.OpenInNewTab {
		return true
	}
	if desired.Group != "" && current.Group != desired.Group {
		return true
	}
	return false
}

func redirectURIsEqual(a, b []RedirectURI) bool {
	if len(a) != len(b) {
		return false
	}
	type key struct {
		MatchingMode    string
		URL             string
		RedirectURIType string
	}
	counts := make(map[key]int, len(a))
	for _, u := range a {
		counts[key(u)]++
	}
	for _, u := range b {
		k := key(u)
		counts[k]--
		if counts[k] < 0 {
			return false
		}
	}
	return true
}

func StringSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aSorted := slices.Clone(a)
	bSorted := slices.Clone(b)
	slices.Sort(aSorted)
	slices.Sort(bSorted)
	return slices.Equal(aSorted, bSorted)
}
