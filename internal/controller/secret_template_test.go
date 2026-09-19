package controller

import (
	"reflect"
	"strings"
	"testing"
)

func TestRenderSecretTemplateContextAndFunctions(t *testing.T) {
	t.Parallel()

	data := secretTemplateData{
		ClientID:              "client-id",
		ClientSecret:          "quote\" slash\\ newline\n tab\t",
		Issuer:                "https://auth.example.com/application/o/app/",
		DiscoveryURL:          "https://auth.example.com/application/o/app/.well-known/openid-configuration",
		AuthorizationEndpoint: "https://auth.example.com/authorize/",
		TokenEndpoint:         "https://auth.example.com/token/",
		UserinfoEndpoint:      "https://auth.example.com/userinfo/",
		JWKSURI:               "https://auth.example.com/jwks/",
		EndSessionEndpoint:    "https://auth.example.com/end-session/",
	}
	templates := map[string]string{
		"context": "{{ .ClientID }}|{{ .ClientSecret }}|{{ .Issuer }}|{{ .DiscoveryURL }}|{{ .AuthorizationEndpoint }}|{{ .TokenEndpoint }}|{{ .UserinfoEndpoint }}|{{ .JWKSURI }}|{{ .EndSessionEndpoint }}",
		"json":    `{"quote":{{ .ClientSecret | quote }},"json":{{ .ClientSecret | toJson }}}`,
		"scalars": `{{ quote 123 }}|{{ toJson 123 }}`,
		"trim":    `{{ .Issuer | trimPrefix "https://" | trimSuffix "/" }}`,
	}

	got, err := renderSecretTemplate(templates, data, nil)
	if err != nil {
		t.Fatalf("renderSecretTemplate() error = %v", err)
	}

	want := map[string][]byte{
		"context": []byte(strings.Join([]string{
			data.ClientID,
			data.ClientSecret,
			data.Issuer,
			data.DiscoveryURL,
			data.AuthorizationEndpoint,
			data.TokenEndpoint,
			data.UserinfoEndpoint,
			data.JWKSURI,
			data.EndSessionEndpoint,
		}, "|")),
		"json":    []byte(`{"quote":"quote\" slash\\ newline\n tab\t","json":"quote\" slash\\ newline\n tab\t"}`),
		"scalars": []byte(`"123"|123`),
		"trim":    []byte("auth.example.com/application/o/app"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("renderSecretTemplate() = %#v, want %#v", got, want)
	}
}

func TestRenderSecretTemplateRejectsInvalidTemplatesWithoutLeakingValues(t *testing.T) {
	t.Parallel()

	var data secretTemplateData
	dataValue := reflect.ValueOf(&data).Elem()
	sensitiveValues := make([]string, 0, dataValue.NumField()+1)
	for i := range dataValue.NumField() {
		field := dataValue.Type().Field(i)
		sentinel := "do-not-leak-" + field.Name
		dataValue.Field(i).SetString(sentinel)
		sensitiveValues = append(sensitiveValues, sentinel)
	}
	sensitiveValues = append(sensitiveValues, "rendered-prefix")
	tests := map[string]struct {
		templateText string
		wantDetail   string
	}{
		"unknown field": {
			templateText: `rendered-prefix-{{ .ClientSecret }}-{{ .Unknown }}`,
			wantDetail:   "Unknown",
		},
		"unknown function": {
			templateText: `{{ doesNotExist .ClientSecret }}`,
			wantDetail:   "doesNotExist",
		},
		"wrong argument type": {
			templateText: `{{ trimPrefix .ClientID 123 }}`,
			wantDetail:   "expected string",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := renderSecretTemplate(
				map[string]string{"BROKEN_KEY": test.templateText},
				data,
				nil,
			)
			if err == nil {
				t.Fatal("renderSecretTemplate() error = nil, want error")
			}
			if got != nil {
				t.Errorf("renderSecretTemplate() result = %#v, want nil", got)
			}
			if !strings.Contains(err.Error(), "BROKEN_KEY") {
				t.Errorf("error %q does not identify Secret key", err)
			}
			if !strings.Contains(err.Error(), test.wantDetail) {
				t.Errorf("error %q does not include useful detail %q", err, test.wantDetail)
			}
			for _, leaked := range sensitiveValues {
				if strings.Contains(err.Error(), leaked) {
					t.Errorf("error %q leaks %q", err, leaked)
				}
			}
		})
	}
}

func TestRenderSecretTemplateReportsFirstKeyDeterministically(t *testing.T) {
	t.Parallel()

	for range 100 {
		_, err := renderSecretTemplate(map[string]string{
			"Z_LAST":  `{{ unknownZ }}`,
			"A_FIRST": `{{ unknownA }}`,
		}, secretTemplateData{}, nil)
		if err == nil {
			t.Fatal("renderSecretTemplate() error = nil, want error")
		}
		if !strings.Contains(err.Error(), "A_FIRST") {
			t.Fatalf("error %q does not identify lexicographically first key", err)
		}
		if strings.Contains(err.Error(), "Z_LAST") {
			t.Fatalf("error %q reports later key", err)
		}
	}
}

func TestRenderSecretTemplatePreservesClientSecretDependentEntries(t *testing.T) {
	t.Parallel()

	templates := map[string]string{
		"direct":       `{{ .ClientSecret }}`,
		"piped":        `{{ .ClientSecret | quote }}`,
		"nested":       `{{ define "credential" }}{{ .ClientSecret }}{{ end }}{{ template "credential" . }}`,
		"nested-chain": `{{ define "credential" }}{{ .ClientSecret }}{{ end }}{{ define "wrapper" }}{{ template "credential" . }}{{ end }}{{ template "wrapper" . }}`,
		"current":      `{{ .ClientID }}|{{ .Issuer }}`,
	}
	previous := map[string][]byte{
		"direct":       []byte("old-direct"),
		"piped":        []byte("old-piped"),
		"nested":       []byte("old-nested"),
		"nested-chain": []byte("old-nested-chain"),
		"current":      []byte("stale-current"),
	}

	got, err := renderSecretTemplate(templates, secretTemplateData{
		ClientID: "new-client-id",
		Issuer:   "new-issuer",
	}, previous)
	if err != nil {
		t.Fatalf("renderSecretTemplate() error = %v", err)
	}

	want := map[string][]byte{
		"direct":       []byte("old-direct"),
		"piped":        []byte("old-piped"),
		"nested":       []byte("old-nested"),
		"nested-chain": []byte("old-nested-chain"),
		"current":      []byte("new-client-id|new-issuer"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("renderSecretTemplate() = %#v, want %#v", got, want)
	}
}

func TestRenderSecretTemplatePreservesWholeContextDependentEntries(t *testing.T) {
	t.Parallel()

	templates := map[string]string{
		"direct": "{" + "{ toJson . }" + "}",
		"nested": "{" + "{ define \"context\" }" + "}" +
			"{" + "{ toJson . }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ template \"context\" . }" + "}",
		"plain": "literal-{" + "{ .ClientID }" + "}",
	}
	initial, err := renderSecretTemplate(templates, secretTemplateData{
		ClientID:     "initial-client-id",
		ClientSecret: "initial-client-secret",
	}, nil)
	if err != nil {
		t.Fatalf("initial renderSecretTemplate() error = %v", err)
	}
	for _, key := range []string{"direct", "nested"} {
		if !strings.Contains(string(initial[key]), `"ClientSecret":"initial-client-secret"`) {
			t.Fatalf("initial %s entry %q does not contain client secret context JSON", key, initial[key])
		}
	}

	got, err := renderSecretTemplate(templates, secretTemplateData{ClientID: "updated-client-id"}, initial)
	if err != nil {
		t.Fatalf("subsequent renderSecretTemplate() error = %v", err)
	}
	for _, key := range []string{"direct", "nested"} {
		if !reflect.DeepEqual(got[key], initial[key]) {
			t.Errorf("%s entry = %q, want exact previous bytes %q", key, got[key], initial[key])
		}
	}
	if want := []byte("literal-updated-client-id"); !reflect.DeepEqual(got["plain"], want) {
		t.Errorf("plain entry = %q, want %q", got["plain"], want)
	}
}

func TestRenderSecretTemplatePreservesRootVariableDependentEntries(t *testing.T) {
	t.Parallel()

	templates := map[string]string{
		"direct":   "{" + "{ toJson $ }" + "}",
		"derived":  "{" + "{ $root := $ }" + "}" + "{" + "{ toJson $root }" + "}",
		"explicit": "{" + "{ $.ClientSecret }" + "}",
		"nested": "{" + "{ define \"root-context\" }" + "}" +
			"{" + "{ toJson $ }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ template \"root-context\" . }" + "}",
		"plain": "literal-{" + "{ .ClientID }" + "}",
	}
	initial, err := renderSecretTemplate(templates, secretTemplateData{
		ClientID:     "initial-client-id",
		ClientSecret: "initial-client-secret",
	}, nil)
	if err != nil {
		t.Fatalf("initial renderSecretTemplate() error = %v", err)
	}
	for _, key := range []string{"direct", "derived", "nested"} {
		if !strings.Contains(string(initial[key]), `"ClientSecret":"initial-client-secret"`) {
			t.Fatalf("initial %s entry %q does not contain client secret context JSON", key, initial[key])
		}
	}
	if got := string(initial["explicit"]); got != "initial-client-secret" {
		t.Fatalf("initial explicit entry = %q, want client secret", got)
	}

	got, err := renderSecretTemplate(templates, secretTemplateData{ClientID: "updated-client-id"}, initial)
	if err != nil {
		t.Fatalf("subsequent renderSecretTemplate() error = %v", err)
	}
	for _, key := range []string{"direct", "derived", "explicit", "nested"} {
		if !reflect.DeepEqual(got[key], initial[key]) {
			t.Errorf("%s entry = %q, want exact previous bytes %q", key, got[key], initial[key])
		}
	}
	if want := []byte("literal-updated-client-id"); !reflect.DeepEqual(got["plain"], want) {
		t.Errorf("plain entry = %q, want %q", got["plain"], want)
	}
}

func TestRenderSecretTemplateRendersReboundNonSecretContexts(t *testing.T) {
	t.Parallel()

	templates := map[string]string{
		"local": "{" + "{ $value := .Issuer }" + "}" + "{" + "{ $value }" + "}",
		"nested": "{" + "{ define \"value\" }" + "}" +
			"{" + "{ . }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ template \"value\" .Issuer }" + "}",
		"with": "{" + "{ with .Issuer }" + "}" + "{" + "{ . }" + "}" + "{" + "{ end }" + "}",
	}

	got, err := renderSecretTemplate(templates, secretTemplateData{Issuer: "current-issuer"}, nil)
	if err != nil {
		t.Fatalf("renderSecretTemplate() error = %v", err)
	}

	want := map[string][]byte{
		"local":  []byte("current-issuer"),
		"nested": []byte("current-issuer"),
		"with":   []byte("current-issuer"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("renderSecretTemplate() = %#v, want %#v", got, want)
	}
}

func TestRenderSecretTemplateHandlesTemplateInvocationWithoutPipeline(t *testing.T) {
	t.Parallel()

	templates := map[string]string{
		"nil-context": "{" + "{ define \"value\" }" + "}" +
			"{" + "{ toJson . }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ template \"value\" }" + "}",
	}

	got, err := renderSecretTemplate(templates, secretTemplateData{}, nil)
	if err != nil {
		t.Fatalf("renderSecretTemplate() error = %v", err)
	}
	if want := []byte("null"); !reflect.DeepEqual(got["nil-context"], want) {
		t.Errorf("nil-context entry = %q, want %q", got["nil-context"], want)
	}
}

func TestRenderSecretTemplateTracksParenthesizedPipelines(t *testing.T) {
	t.Parallel()

	templates := map[string]string{
		"root":      "{" + "{ toJson (toJson .) }" + "}",
		"nonsecret": "{" + "{ toJson (toJson .Issuer) }" + "}",
	}
	initial, err := renderSecretTemplate(templates, secretTemplateData{
		ClientSecret: "initial-client-secret",
		Issuer:       "initial-issuer",
	}, nil)
	if err != nil {
		t.Fatalf("initial renderSecretTemplate() error = %v", err)
	}
	if !strings.Contains(string(initial["root"]), "initial-client-secret") {
		t.Fatalf("initial root entry %q does not contain client secret", initial["root"])
	}

	got, err := renderSecretTemplate(templates, secretTemplateData{Issuer: "updated-issuer"}, initial)
	if err != nil {
		t.Fatalf("subsequent renderSecretTemplate() error = %v", err)
	}
	if !reflect.DeepEqual(got["root"], initial["root"]) {
		t.Errorf("root entry = %q, want exact previous bytes %q", got["root"], initial["root"])
	}
	if want := []byte(`"\"updated-issuer\""`); !reflect.DeepEqual(got["nonsecret"], want) {
		t.Errorf("nonsecret entry = %q, want %q", got["nonsecret"], want)
	}
}

func TestRenderSecretTemplateTracksOuterVariableAssignmentsAcrossBranches(t *testing.T) {
	t.Parallel()

	templates := map[string]string{
		"if-root": "{" + "{ $value := .Issuer }" + "}" +
			"{" + "{ if .Issuer }" + "}" +
			"{" + "{ $value = $ }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ toJson $value }" + "}",
		"if-else-root": "{" + "{ $value := .Issuer }" + "}" +
			"{" + "{ if .Issuer }" + "}" +
			"{" + "{ $value = .Issuer }" + "}" +
			"{" + "{ else }" + "}" +
			"{" + "{ $value = $ }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ toJson $value }" + "}",
		"with-root": "{" + "{ $value := .Issuer }" + "}" +
			"{" + "{ with .Issuer }" + "}" +
			"{" + "{ $value = $ }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ toJson $value }" + "}",
		"if-scalar": "{" + "{ $value := .ClientID }" + "}" +
			"{" + "{ if .Issuer }" + "}" +
			"{" + "{ $value = .Issuer }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ $value }" + "}",
		"with-scalar": "{" + "{ $value := .ClientID }" + "}" +
			"{" + "{ with .Issuer }" + "}" +
			"{" + "{ $value = . }" + "}" +
			"{" + "{ else }" + "}" +
			"{" + "{ $value = .ClientID }" + "}" +
			"{" + "{ end }" + "}" +
			"{" + "{ $value }" + "}",
	}
	initial, err := renderSecretTemplate(templates, secretTemplateData{
		ClientID:     "initial-client-id",
		ClientSecret: "initial-client-secret",
		Issuer:       "initial-issuer",
	}, nil)
	if err != nil {
		t.Fatalf("initial renderSecretTemplate() error = %v", err)
	}
	for _, key := range []string{"if-root", "with-root"} {
		if !strings.Contains(string(initial[key]), "initial-client-secret") {
			t.Fatalf("initial %s entry %q does not contain client secret", key, initial[key])
		}
	}
	if got := string(initial["if-else-root"]); got != `"initial-issuer"` {
		t.Fatalf("initial if-else-root entry = %q, want selected scalar branch", got)
	}

	got, err := renderSecretTemplate(templates, secretTemplateData{
		ClientID: "updated-client-id",
		Issuer:   "updated-issuer",
	}, initial)
	if err != nil {
		t.Fatalf("subsequent renderSecretTemplate() error = %v", err)
	}
	for _, key := range []string{"if-root", "if-else-root", "with-root"} {
		if !reflect.DeepEqual(got[key], initial[key]) {
			t.Errorf("%s entry = %q, want exact previous bytes %q", key, got[key], initial[key])
		}
	}
	for _, key := range []string{"if-scalar", "with-scalar"} {
		if want := []byte("updated-issuer"); !reflect.DeepEqual(got[key], want) {
			t.Errorf("%s entry = %q, want %q", key, got[key], want)
		}
	}
}

func TestRenderSecretTemplateMissingPreviousValueIsAtomic(t *testing.T) {
	t.Parallel()

	got, err := renderSecretTemplate(
		map[string]string{
			"A_RENDERED": `{{ .ClientID }}`,
			"B_SECRET":   `{{ .ClientSecret | quote }}`,
		},
		secretTemplateData{ClientID: "must-not-be-returned"},
		map[string][]byte{},
	)
	if err == nil {
		t.Fatal("renderSecretTemplate() error = nil, want error")
	}
	if got != nil {
		t.Errorf("renderSecretTemplate() result = %#v, want nil", got)
	}
	if !strings.Contains(err.Error(), "B_SECRET") {
		t.Errorf("error %q does not identify Secret key", err)
	}
	if strings.Contains(err.Error(), "must-not-be-returned") {
		t.Errorf("error %q leaks rendered value", err)
	}
}
