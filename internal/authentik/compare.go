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
		counts[key{u.MatchingMode, u.URL, u.RedirectURIType}]++
	}
	for _, u := range b {
		k := key{u.MatchingMode, u.URL, u.RedirectURIType}
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
