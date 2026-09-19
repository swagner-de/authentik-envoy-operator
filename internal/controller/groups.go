package controller

import (
	"context"
	"fmt"

	v1alpha1 "github.com/authentik-envoy-operator/authentik-envoy-operator/api/v1alpha1"
	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
)

// resolveGroups resolves each spec group to its Authentik UUID, creating groups
// with create:true when absent. Returns the name→UUID map and the names of the
// groups the operator created this call.
func resolveGroups(ctx context.Context, api *authentik.Client, app *v1alpha1.OIDCApplication) (map[string]string, []string, error) {
	byName := make(map[string]string, len(app.Spec.Groups))
	var created []string
	for _, g := range app.Spec.Groups {
		existing, err := api.GetGroupByName(ctx, g.Name)
		if err != nil {
			// Real API/transport error — surface it so the reconcile retries
			// instead of mistaking a transient failure for "group absent" and
			// creating a duplicate.
			return nil, nil, fmt.Errorf("looking up group %q: %w", g.Name, err)
		}
		if existing != nil {
			byName[g.Name] = existing.PK
			continue
		}
		if !g.Create {
			return nil, nil, fmt.Errorf("group %q not found and create is false", g.Name)
		}
		grp, cerr := api.CreateGroup(ctx, g.Name)
		if cerr != nil {
			return nil, nil, fmt.Errorf("creating group %q: %w", g.Name, cerr)
		}
		byName[g.Name] = grp.PK
		created = append(created, g.Name)
	}
	return byName, created, nil
}
