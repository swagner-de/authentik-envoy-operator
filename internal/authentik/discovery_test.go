package authentik_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/authentik-envoy-operator/authentik-envoy-operator/internal/authentik"
)

func TestGetDiscoveryDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/application/o/app/.well-known/openid-configuration" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"issuer":"` + "http://" + r.Host + `/application/o/app/",
			"authorization_endpoint":"http://x/authorize/",
			"token_endpoint":"http://x/token/",
			"userinfo_endpoint":"http://x/userinfo/",
			"jwks_uri":"http://x/jwks/",
			"end_session_endpoint":"http://x/end-session/"}`))
	}))
	defer server.Close()

	client := authentik.NewClient(server.URL, "token")
	doc, err := client.GetDiscoveryDocument(context.Background(), server.URL+"/application/o/app/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.TokenEndpoint != "http://x/token/" || doc.JWKSURI != "http://x/jwks/" {
		t.Errorf("unexpected discovery doc: %+v", doc)
	}
}
