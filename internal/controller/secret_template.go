package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"text/template/parse"
)

type secretTemplateData struct {
	ClientID              string
	ClientSecret          string
	Issuer                string
	DiscoveryURL          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	JWKSURI               string
	EndSessionEndpoint    string
}

func renderSecretTemplate(templates map[string]string, data secretTemplateData, previous map[string][]byte) (map[string][]byte, error) {
	keys := make([]string, 0, len(templates))
	for key := range templates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := make(map[string][]byte, len(templates))
	for _, key := range keys {
		tmpl, err := template.New(key).Option("missingkey=error").Funcs(template.FuncMap{
			"quote":  quoteJSON,
			"toJson": marshalJSON,
			"trimPrefix": func(prefix, value string) string {
				return strings.TrimPrefix(value, prefix)
			},
			"trimSuffix": func(suffix, value string) string {
				return strings.TrimSuffix(value, suffix)
			},
		}).Parse(templates[key])
		if err != nil {
			return nil, fmt.Errorf("parse Secret key %q: %s", key, sanitizeTemplateError(err, data))
		}

		if data.ClientSecret == "" && templateUsesClientSecret(tmpl) {
			value, ok := previous[key]
			if !ok {
				return nil, fmt.Errorf("render Secret key %q: previous value required when client secret is unavailable", key)
			}
			result[key] = append([]byte(nil), value...)
			continue
		}

		var rendered bytes.Buffer
		if err := tmpl.Execute(&rendered, data); err != nil {
			return nil, fmt.Errorf("render Secret key %q: %s", key, sanitizeTemplateError(err, data))
		}
		result[key] = rendered.Bytes()
	}

	return result, nil
}

func quoteJSON(value any) (string, error) {
	return marshalJSON(fmt.Sprint(value))
}

func marshalJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	return string(encoded), err
}

func sanitizeTemplateError(err error, data secretTemplateData) string {
	detail := err.Error()
	values := []string{
		data.ClientID,
		data.ClientSecret,
		data.Issuer,
		data.DiscoveryURL,
		data.AuthorizationEndpoint,
		data.TokenEndpoint,
		data.UserinfoEndpoint,
		data.JWKSURI,
		data.EndSessionEndpoint,
	}
	sort.Slice(values, func(i, j int) bool {
		return len(values[i]) > len(values[j])
	})
	for _, value := range values {
		if value != "" {
			detail = strings.ReplaceAll(detail, value, "[REDACTED]")
		}
	}
	return detail
}

func templateUsesClientSecret(tmpl *template.Template) bool {
	analyzer := secretDependencyAnalyzer{
		tmpl:     tmpl,
		visiting: make(map[string]bool),
	}
	return analyzer.analyzeTemplate(tmpl, true)
}

type secretDependencyAnalyzer struct {
	tmpl     *template.Template
	visiting map[string]bool
}

type dependencyScope struct {
	dotMayContainRoot bool
	variables         map[string]bool
}

func (a *secretDependencyAnalyzer) analyzeTemplate(tmpl *template.Template, dotMayContainRoot bool) bool {
	visitKey := fmt.Sprintf("%s:%t", tmpl.Name(), dotMayContainRoot)
	if a.visiting[visitKey] {
		return false
	}
	a.visiting[visitKey] = true
	defer delete(a.visiting, visitKey)

	scope := dependencyScope{
		dotMayContainRoot: dotMayContainRoot,
		variables:         map[string]bool{"$": dotMayContainRoot},
	}
	return a.nodeUsesClientSecret(tmpl.Tree.Root, &scope)
}

func (a *secretDependencyAnalyzer) nodeUsesClientSecret(node parse.Node, scope *dependencyScope) bool {
	if node == nil {
		return false
	}

	switch node := node.(type) {
	case *parse.ListNode:
		if node == nil {
			return false
		}
		for _, child := range node.Nodes {
			if a.nodeUsesClientSecret(child, scope) {
				return true
			}
		}
	case *parse.ActionNode:
		mayContainRoot, depends := a.analyzePipe(node.Pipe, scope)
		return depends || len(node.Pipe.Decl) == 0 && mayContainRoot
	case *parse.PipeNode:
		_, depends := a.analyzePipe(node, scope)
		return depends
	case *parse.FieldNode:
		return scope.dotMayContainRoot && len(node.Ident) > 0 && node.Ident[0] == "ClientSecret"
	case *parse.DotNode:
		return scope.dotMayContainRoot
	case *parse.VariableNode:
		return a.variableUsesClientSecret(node, scope)
	case *parse.ChainNode:
		baseMayContainRoot := a.nodeMayContainRoot(node.Node, scope)
		if baseMayContainRoot && len(node.Field) > 0 && node.Field[0] == "ClientSecret" {
			return true
		}
		return false
	case *parse.IfNode:
		return a.analyzeBranch(&node.BranchNode, scope, false)
	case *parse.RangeNode:
		return a.analyzeBranch(&node.BranchNode, scope, true)
	case *parse.WithNode:
		return a.analyzeBranch(&node.BranchNode, scope, true)
	case *parse.TemplateNode:
		dotMayContainRoot := false
		depends := false
		if node.Pipe != nil {
			dotMayContainRoot, depends = a.analyzePipe(node.Pipe, scope)
		}
		associated := a.tmpl.Lookup(node.Name)
		return depends || associated != nil && a.analyzeTemplate(associated, dotMayContainRoot)
	}

	return false
}

func (a *secretDependencyAnalyzer) analyzeBranch(branch *parse.BranchNode, scope *dependencyScope, rebindDot bool) bool {
	outerVariables := make(map[string]struct{}, len(scope.variables))
	for name := range scope.variables {
		outerVariables[name] = struct{}{}
	}
	if !branch.Pipe.IsAssign {
		for _, variable := range branch.Pipe.Decl {
			delete(outerVariables, variable.Ident[0])
		}
	}

	controlScope := scope.clone()
	valueMayContainRoot, depends := a.analyzePipe(branch.Pipe, controlScope)
	if depends {
		return true
	}

	bodyScope := controlScope.clone()
	if rebindDot {
		bodyScope.dotMayContainRoot = valueMayContainRoot
	}
	if a.nodeUsesClientSecret(branch.List, bodyScope) {
		return true
	}

	elseScope := controlScope.clone()
	if a.nodeUsesClientSecret(branch.ElseList, elseScope) {
		return true
	}
	a.mergeBranchVariables(scope, outerVariables, bodyScope, elseScope)
	return false
}

func (a *secretDependencyAnalyzer) mergeBranchVariables(scope *dependencyScope, names map[string]struct{}, branches ...*dependencyScope) {
	for name := range names {
		scope.variables[name] = false
		for _, branch := range branches {
			if branch.variables[name] {
				scope.variables[name] = true
				break
			}
		}
	}
}

func (a *secretDependencyAnalyzer) analyzePipe(pipe *parse.PipeNode, scope *dependencyScope) (bool, bool) {
	if pipe == nil {
		return false, false
	}

	mayContainRoot := false
	depends := false
	for i, command := range pipe.Cmds {
		mayContainRoot, depends = a.analyzeCommand(command, scope, mayContainRoot, i > 0)
		if depends {
			return false, true
		}
	}
	for _, variable := range pipe.Decl {
		scope.variables[variable.Ident[0]] = mayContainRoot
	}
	return mayContainRoot, false
}

func (a *secretDependencyAnalyzer) analyzeCommand(command *parse.CommandNode, scope *dependencyScope, pipedRoot, hasPipe bool) (bool, bool) {
	argumentRoots := make([]bool, len(command.Args))
	for i, argument := range command.Args {
		if a.nodeUsesClientSecret(argument, scope) && !a.nodeMayContainRoot(argument, scope) {
			return false, true
		}
		argumentRoots[i] = a.nodeMayContainRoot(argument, scope)
	}

	if len(command.Args) == 1 && !hasPipe {
		return argumentRoots[0], false
	}
	if pipedRoot {
		return false, true
	}
	for _, mayContainRoot := range argumentRoots[1:] {
		if mayContainRoot {
			return false, true
		}
	}
	return false, false
}

func (a *secretDependencyAnalyzer) nodeMayContainRoot(node parse.Node, scope *dependencyScope) bool {
	switch node := node.(type) {
	case *parse.DotNode:
		return scope.dotMayContainRoot
	case *parse.VariableNode:
		return a.variableMayContainRoot(node, scope)
	case *parse.ChainNode:
		return len(node.Field) == 0 && a.nodeMayContainRoot(node.Node, scope)
	case *parse.FieldNode:
		return false
	case *parse.PipeNode:
		mayContainRoot, _ := a.analyzePipe(node, scope)
		return mayContainRoot
	}
	return false
}

func (a *secretDependencyAnalyzer) variableMayContainRoot(node *parse.VariableNode, scope *dependencyScope) bool {
	return len(node.Ident) == 1 && scope.variables[node.Ident[0]]
}

func (a *secretDependencyAnalyzer) variableUsesClientSecret(node *parse.VariableNode, scope *dependencyScope) bool {
	if len(node.Ident) == 0 || !scope.variables[node.Ident[0]] {
		return false
	}
	return len(node.Ident) == 1 || node.Ident[1] == "ClientSecret"
}

func (scope *dependencyScope) clone() *dependencyScope {
	cloned := &dependencyScope{
		dotMayContainRoot: scope.dotMayContainRoot,
		variables:         make(map[string]bool, len(scope.variables)),
	}
	for name, mayContainRoot := range scope.variables {
		cloned.variables[name] = mayContainRoot
	}
	return cloned
}
