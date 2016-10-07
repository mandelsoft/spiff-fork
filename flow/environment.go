package flow

import (
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mandelsoft/spiff/debug"
	"github.com/mandelsoft/spiff/dynaml"
	"github.com/mandelsoft/spiff/yaml"
)

type Scope struct {
	local map[string]yaml.Node
	next  *Scope
	root  *Scope
}

func newScope(outer *Scope, local map[string]yaml.Node) *Scope {
	scope := &Scope{local, outer, nil}
	if outer == nil {
		scope.root = scope
	} else {
		scope.root = outer.root
	}
	return scope
}

type DefaultEnvironment struct {
	scope *Scope
	path  []string

	stubs      []yaml.Node
	stubPath   []string
	sourceName string

	currentSourceName string

	local map[string]yaml.Node
}

func (e DefaultEnvironment) Path() []string {
	return e.path
}

func (e DefaultEnvironment) StubPath() []string {
	return e.stubPath
}

func (e DefaultEnvironment) SourceName() string {
	return e.sourceName
}

func (e DefaultEnvironment) CurrentSourceName() string {
	return e.currentSourceName
}

func (e DefaultEnvironment) GetLocalBinding() map[string]yaml.Node {
	return e.local
}

func (e DefaultEnvironment) FindFromRoot(path []string) (yaml.Node, bool) {
	if e.scope == nil {
		return nil, false
	}

	return yaml.FindR(true, yaml.NewNode(e.scope.root.local, "scope"), path...)
}

func (e DefaultEnvironment) FindReference(path []string) (yaml.Node, bool) {
	root, found := resolveSymbol(&e, path[0], e.scope)
	if !found {
		return nil, false
	}

	return yaml.FindR(true, root, path[1:]...)
}

func (e DefaultEnvironment) FindInStubs(path []string) (yaml.Node, bool) {
	for _, stub := range e.stubs {
		val, found := yaml.Find(stub, path...)
		if found {
			return val, true
		}
	}

	return nil, false
}

func (e DefaultEnvironment) WithSource(source string) dynaml.Binding {
	e.sourceName = source
	return e
}

func (e DefaultEnvironment) WithScope(step map[string]yaml.Node) dynaml.Binding {
	e.scope = newScope(e.scope, step)
	e.local = map[string]yaml.Node{}
	return e
}

func (e DefaultEnvironment) WithLocalScope(step map[string]yaml.Node) dynaml.Binding {
	e.scope = newScope(e.scope, step)
	e.local = step
	return e
}

func (e DefaultEnvironment) WithPath(step string) dynaml.Binding {
	newPath := make([]string, len(e.path))
	copy(newPath, e.path)
	e.path = append(newPath, step)

	newPath = make([]string, len(e.stubPath))
	copy(newPath, e.stubPath)
	e.stubPath = append(newPath, step)

	e.local = map[string]yaml.Node{}
	return e
}

func (e DefaultEnvironment) RedirectOverwrite(path []string) dynaml.Binding {
	e.stubPath = path
	return e
}

func (e DefaultEnvironment) Flow(source yaml.Node, shouldOverride bool) (yaml.Node, dynaml.Status) {
	result := source

	for {
		debug.Debug("@@@ loop:  %+v\n", result)
		next := flow(result, e, shouldOverride)
		debug.Debug("@@@ --->   %+v\n", next)

		if reflect.DeepEqual(result, next) {
			break
		}

		result = next
	}
	debug.Debug("@@@ Done\n")
	unresolved := dynaml.FindUnresolvedNodes(result)
	if len(unresolved) > 0 {
		return result, dynaml.UnresolvedNodes{unresolved}
	}

	return result, nil
}

func NewEnvironment(stubs []yaml.Node, source string) dynaml.Binding {
	return DefaultEnvironment{stubs: stubs, sourceName: source, currentSourceName: source}
}

func resolveSymbol(env *DefaultEnvironment, name string, scope *Scope) (yaml.Node, bool) {

	if name == "__ctx" {
		return createContext(env), true
	}
	for scope != nil {
		val := scope.local[name]
		if val != nil {
			return val, true
		}
		scope = scope.next
	}

	return nil, false
}

func createContext(env *DefaultEnvironment) yaml.Node {
	ctx := make(map[string]yaml.Node)

	read, err := filepath.EvalSymlinks(env.CurrentSourceName())
	if err != nil {
		read = env.CurrentSourceName()
	}
	ctx["FILE"] = node(env.CurrentSourceName())
	ctx["DIR"] = node(filepath.Dir(env.CurrentSourceName()))
	ctx["RESOLVED_FILE"] = node(read)
	ctx["RESOLVED_DIR"] = node(filepath.Dir(read))

	ctx["PATHNAME"] = node(strings.Join(env.Path(), "."))

	path := make([]yaml.Node, len(env.Path()))
	for i, v := range env.Path() {
		path[i] = node(v)
	}
	ctx["PATH"] = node(path)
	return node(ctx)
}

func node(val interface{}) yaml.Node {
	return yaml.NewNode(val, "__ctx")
}
