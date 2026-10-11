package privacylint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// listedPackage is one package from `go list -json`.
type listedPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Export     string
	DepOnly    bool
	Module     *struct {
		Dir  string
		Main bool
	}
	Error *struct {
		Err string
	}
}

// goList runs `go list -deps -export -json` in dir for GOOS goos. The export
// data that it names lets go/types read each dependency without its source.
// -mod=readonly keeps go.mod and go.sum as they are. A module that the module
// cache does not have (a fresh clone, or a module that only the Windows build
// uses) is downloaded as for go test, and go.sum checks it.
func goList(dir, goos string, patterns ...string) ([]listedPackage, error) {
	args := append([]string{"list", "-deps", "-export",
		"-json=ImportPath,Dir,GoFiles,Export,DepOnly,Module,Error"}, patterns...)
	//privacy:allow outbound CL 119: runs the local go command to read the build; it downloads only modules that go.sum names
	cmd := exec.Command("go", args...) //nolint:gosec // G204: the go command with fixed flags and package patterns from the caller
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0",
		"GOFLAGS=-mod=readonly", "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list (GOOS=%s) failed: %w: %s", goos, err, strings.TrimSpace(stderr.String()))
	}
	var pkgs []listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go list output: %w", err)
		}
		if p.Error != nil {
			return nil, fmt.Errorf("go list: %s: %s", p.ImportPath, p.Error.Err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// exportIndex maps import paths to the export data files that go list names,
// for one module directory and GOOS. The rule fixtures share it, so go list
// runs once for the module and once for each package that the module does not
// use.
type exportIndex struct {
	mu        sync.Mutex
	dir, goos string
	listed    []listedPackage
	exports   map[string]string
}

var indexes = struct {
	sync.Mutex
	m map[[2]string]*exportIndex
}{m: map[[2]string]*exportIndex{}}

// indexFor returns the export index of the module in dir for GOOS goos.
func indexFor(dir, goos string) (*exportIndex, error) {
	abs, err := findModuleRoot(dir)
	if err != nil {
		return nil, err
	}
	indexes.Lock()
	defer indexes.Unlock()
	key := [2]string{abs, goos}
	if x, ok := indexes.m[key]; ok {
		return x, nil
	}
	listed, err := goList(abs, goos, "./...")
	if err != nil {
		return nil, err
	}
	x := &exportIndex{dir: abs, goos: goos, listed: listed, exports: map[string]string{}}
	x.add(listed)
	indexes.m[key] = x
	return x, nil
}

// findModuleRoot returns the directory that holds the go.mod of the module that
// dir is in, so that go list ./... lists the whole module from any directory
// in it.
func findModuleRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("no go.mod in %s or a directory above it", abs)
		}
	}
}

func (x *exportIndex) add(pkgs []listedPackage) {
	for _, p := range pkgs {
		if p.Export != "" {
			x.exports[p.ImportPath] = p.Export
		}
	}
}

// file returns the export data file of the package path.
func (x *exportIndex) file(path string) (string, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if file, ok := x.exports[path]; ok {
		return file, nil
	}
	pkgs, err := goList(x.dir, x.goos, path)
	if err != nil {
		return "", err
	}
	x.add(pkgs)
	if file, ok := x.exports[path]; ok {
		return file, nil
	}
	return "", fmt.Errorf("no export data for %s", path)
}

// importer returns a go/types importer that reads export data into fset.
func (x *exportIndex) importer(fset *token.FileSet) types.Importer {
	return importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, err := x.file(path)
		if err != nil {
			return nil, err
		}
		return os.Open(file) //nolint:gosec // G304: an export data file that go list named
	})
}

// parseFile parses one Go file with its comments. name is the path that
// findings show.
func parseFile(fset *token.FileSet, name string, src []byte) (*fileInfo, error) {
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	return &fileInfo{name: name, ast: f, src: src}, nil
}

// checkPackage type-checks files as the package path.
func checkPackage(fset *token.FileSet, imp types.Importer, path string, files []*fileInfo) (*pkgInfo, error) {
	asts := make([]*ast.File, len(files))
	for i, f := range files {
		asts[i] = f.ast
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: imp}
	tpkg, err := conf.Check(path, fset, asts, info)
	if err != nil {
		return nil, fmt.Errorf("type check %s failed: %w", path, err)
	}
	p := &pkgInfo{types: tpkg, info: info, files: files}
	for _, f := range files {
		f.pkg = p
	}
	return p, nil
}

// loadModule type-checks every package of the main module in dir, as the
// go command builds it for GOOS goos. Test files are not loaded: tests use
// query names and addresses on purpose.
func loadModule(dir, goos string) (*unit, error) {
	x, err := indexFor(dir, goos)
	if err != nil {
		return nil, err
	}
	u := &unit{fset: token.NewFileSet()}
	imp := x.importer(u.fset)
	for _, lp := range x.listed {
		if lp.DepOnly || lp.Module == nil || !lp.Module.Main {
			continue
		}
		var files []*fileInfo
		for _, name := range lp.GoFiles {
			path := filepath.Join(lp.Dir, name)
			src, err := os.ReadFile(path) //nolint:gosec // G304: a Go file of the module that go list named
			if err != nil {
				return nil, err
			}
			rel, err := filepath.Rel(lp.Module.Dir, path)
			if err != nil {
				return nil, err
			}
			f, err := parseFile(u.fset, filepath.ToSlash(rel), src)
			if err != nil {
				return nil, err
			}
			files = append(files, f)
		}
		p, err := checkPackage(u.fset, imp, lp.ImportPath, files)
		if err != nil {
			return nil, err
		}
		u.pkgs = append(u.pkgs, p)
	}
	return u, nil
}

// loadFiles type-checks the given sources as one package with import path
// pkgPath, for GOOS goos. Imports resolve through the module in dir.
func loadFiles(dir, goos, pkgPath string, sources map[string]string) (*unit, error) {
	x, err := indexFor(dir, goos)
	if err != nil {
		return nil, err
	}
	u := &unit{fset: token.NewFileSet()}
	imp := x.importer(u.fset)
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	var files []*fileInfo
	for _, name := range names {
		f, err := parseFile(u.fset, name, []byte(sources[name]))
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	p, err := checkPackage(u.fset, imp, pkgPath, files)
	if err != nil {
		return nil, err
	}
	u.pkgs = []*pkgInfo{p}
	return u, nil
}
