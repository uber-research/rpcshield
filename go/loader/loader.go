package loader

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// SimplePackage is a simplified version of the packages.Package, see LoadSimplePackage for more details.
type SimplePackage struct {
	Dir       string
	PkgPath   string
	Fset      *token.FileSet
	Files     []*ast.File
	Types     *types.Package
	TypesInfo *types.Info
}

// LoadSimplePackage loads a simplified version of package, where only ASTs and _local_ (i.e., no
// import resolution) types (only Defs and Uses) are loaded. It is meant to be a much faster
// alternative to packages.Load for AST-level analyses, where partial local object resolution can
// be handy.
//
// If filter is not nil, only files passing through the filter (and ending in ".go") are loaded.
func LoadSimplePackage(dir string, root string, filter func(entry fs.DirEntry) bool) (*SimplePackage, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".go") || (filter != nil && !filter(entry)) {
			continue
		}

		node, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.AllErrors|parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parsing file %q: %w", entry.Name(), err)
		}
		files = append(files, node)
	}

	// Do a partial type check.
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Defs:  make(map[*ast.Ident]types.Object),
		Uses:  make(map[*ast.Ident]types.Object),
	}

	// Since we are not doing import resolution (i.e., by giving a nil Importer), there will be
	// errors from the type checker, which we can safely ignore.
	pkgPath, err := filepath.Rel(filepath.Join(root, "src"), dir)
	if err != nil {
		return nil, fmt.Errorf("getting package path: %w", err)
	}
	pkgPath = strings.TrimSuffix(pkgPath, string(filepath.Separator))
	pkg, _ := (&types.Config{
		Importer: nil,                // Intentionally not doing import resolution.
		Error:    func(err error) {}, // Ignoring type errors.
	}).Check(pkgPath, fset, files, info)

	return &SimplePackage{
		Dir:       dir,
		Fset:      fset,
		Types:     pkg,
		TypesInfo: info,
		PkgPath:   pkgPath,
		Files:     files,
	}, nil
}

// LoadAll loads all packages under the go path.
func LoadAll(goPath string, cdeps []string) ([]*packages.Package, error) {
	cfg, err := config(goPath, cdeps)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}

	return pkgs, nil
}

// config returns the packages.Config for loading the packages with the given GOPATH.
func config(goPath string, cdeps []string) (*packages.Config, error) {
	// Convert the GOPATH to an absolute path if it is not. This is required for the GOPATH env
	// to work with the package loaders.
	goPath, err := filepath.Abs(goPath)
	if err != nil {
		return nil, fmt.Errorf("get absolute path: %w", err)
	}

	return &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | /*packages.NeedCompiledGoFiles |*/
			packages.NeedImports | packages.NeedDeps | /*packages.NeedExportFile |*/
			packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo,
		/*packages.NeedTypesSizes | packages.NeedEmbedFiles | packages.NeedEmbedPatterns | packages.NeedModule*/
		Dir:        goPath,
		Env:        env(goPath, cdeps),
		BuildFlags: []string{"-buildvcs=false"},
	}, nil
}

// env returns the environment variables needed for loading the packages for the GOPATH.
// The input path _must_ be an absolute path.
func env(goPath string, cdeps []string) []string {
	e := append(os.Environ(), "GO111MODULE=off", "GOPATH="+goPath, "GOFLAGS=-buildvcs=false")
	// `go list` shells out to `git rev-parse --show-toplevel` from goPath regardless of
	// -buildvcs=false. Under Bazel sandboxing, goPath sits in a runfiles tree with no reachable
	// .git (the sandbox doesn't bind-mount repo ancestors), so that git invocation fails and `go
	// list` treats it as fatal. Point git at a scratch repo via GIT_DIR/GIT_WORK_TREE so the
	// rev-parse trivially succeeds; the reported toplevel is discarded since VCS stamping is off.
	if gitDir, workTree, ok := scratchGitRepo(); ok {
		e = append(e, "GIT_DIR="+gitDir, "GIT_WORK_TREE="+workTree,
			// Ignore the user's global/system git config (hooks, filters, credential helpers) —
			// this repo only exists to make `rev-parse --show-toplevel` succeed.
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "HOME="+workTree)
	}
	if len(cdeps) == 0 {
		return e
	}

	// This enables our lifted directory to correctly read the C/C++ libraries.
	//
	// cdeps are the flags harvested from Bazel (include paths and C/C++ language
	// standard flags). cgo routes flags by source language: C sources (.c) are
	// compiled with CGO_CPPFLAGS+CGO_CFLAGS, and C++ sources (.cc/.cpp) with
	// CGO_CPPFLAGS+CGO_CXXFLAGS. Include paths are language-agnostic, so they go
	// to all three. A language standard flag must reach only its own compiler:
	// a C++ standard (-std=c++NN) placed in CGO_CFLAGS or the shared CGO_CPPFLAGS
	// would make the C compiler reject every .c cgo source ("-std=c++NN is valid
	// for C++ but not for C"), and vice versa. So route -std flags by language.
	var common, cOnly, cxxOnly []string
	for _, f := range cdeps {
		switch {
		case isCXXStdFlag(f):
			cxxOnly = append(cxxOnly, f)
		case isCStdFlag(f):
			cOnly = append(cOnly, f)
		default:
			common = append(common, f)
		}
	}

	join := func(a, b []string) string { return strings.Join(append(append([]string{}, a...), b...), " ") }
	e = append(e,
		"CGO_ENABLED=1",
		"CGO_CFLAGS="+join(common, cOnly),
		"CGO_CXXFLAGS="+join(common, cxxOnly),
		"CGO_CPPFLAGS="+strings.Join(common, " "),
	)
	return e
}

var (
	scratchGitOnce        sync.Once
	scratchGitDir         string
	scratchGitWorkTree    string
	scratchGitInitSuccess bool
)

// scratchGitRepo lazily creates an empty git repository (by hand, without shelling out to `git
// init` — some `git` wrappers on PATH invoke unrelated tooling on init that isn't available in
// this context) in a temp directory, reused for the lifetime of the process, purely so `git
// rev-parse --show-toplevel` has something to succeed against (see env above).
func scratchGitRepo() (gitDir, workTree string, ok bool) {
	scratchGitOnce.Do(func() {
		dir, err := os.MkdirTemp("", "rpcshield-scratch-git")
		if err != nil {
			return
		}
		dotGit := filepath.Join(dir, ".git")
		if err := os.MkdirAll(filepath.Join(dotGit, "objects"), 0o755); err != nil {
			return
		}
		if err := os.MkdirAll(filepath.Join(dotGit, "refs"), 0o755); err != nil {
			return
		}
		if err := os.WriteFile(filepath.Join(dotGit, "HEAD"), []byte("ref: refs/heads/master\n"), 0o644); err != nil {
			return
		}
		scratchGitDir = dotGit
		scratchGitWorkTree = dir
		scratchGitInitSuccess = true
	})
	return scratchGitDir, scratchGitWorkTree, scratchGitInitSuccess
}

// DefaultRootDirName is the ancestor directory name LoadWithGoPath/LoadSSAWithGoPath search for
// in a large monorepo, where rpcshield lives under src/example.internal/..., so it is always
// an ancestor of any rpcshield package's working directory. Forks with a different repo layout
// should pass a marker matching their own layout instead (e.g. their Bazel workspace name, which
// is the top-level ancestor directory name inside the runfiles tree during `bazel test`).
const DefaultRootDirName = "example.internal"

// LoadWithGoPath takes an analysis path `analPath`, which should be already preapred with go_path in bazel,
// and a specfic location `loadPath` that needs to be loaded.
// This is used only by tests since it is a very common operation.
//
// rootDirName is the ancestor directory name to search for (see DefaultRootDirName): the caller's
// working directory could be nested arbitrarily deep inside the repo, so LoadWithGoPath walks up
// the directory tree until it finds a directory with this name, then descends into analPath from
// there.
func LoadWithGoPath(rootDirName string, analPath []string, loadPath string) (entryPkg *packages.Package, allPkgs []*packages.Package, err error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("get working directory: %w", err)
	}

	curDir := dir
	for {
		baseDir := filepath.Base(curDir)
		parentDir := filepath.Dir(curDir)
		if baseDir == rootDirName || parentDir == curDir {
			break
		}
		curDir = parentDir
	}

	basePath := filepath.Base(curDir)
	if basePath != rootDirName {
		return nil, nil, fmt.Errorf("could not find %q directory", rootDirName)
	}
	// From there, we can easily locate the code directory.
	path := append([]string{curDir}, analPath...)
	loadDir := filepath.Join(path...)
	cdeps := []string{} // no cdeps for now.

	pkgs, err := LoadAll(loadDir, cdeps)
	if err != nil || len(pkgs) == 0 {
		return nil, nil, fmt.Errorf("load packages: %w", err)
	}

	// Now find the entry package.
	expectedEntryPkg := loadPath
	for _, pkg := range pkgs {
		if pkg.PkgPath == expectedEntryPkg {
			return pkg, pkgs, nil
		}
	}

	return nil, nil, fmt.Errorf("could not find package %q", expectedEntryPkg)
}

// LoadSSAWithGoPath loads the SSA program and corresponding packages.
// This is used only by tests since it is a very common operation.
// See LoadWithGoPath for the meaning of rootDirName.
func LoadSSAWithGoPath(rootDirName string, path []string, loadPath string) (*ssa.Program, *packages.Package, []*packages.Package, error) {
	entryPkg, allPkgs, err := LoadWithGoPath(rootDirName, path, loadPath)
	if err != nil {
		return nil, nil, nil, err
	}

	ssaProg, _ := ssautil.AllPackages(allPkgs, ssa.InstantiateGenerics|ssa.GlobalDebug)
	ssaProg.Build()

	return ssaProg, entryPkg, allPkgs, nil
}

// isCXXStdFlag reports whether the flag selects a C++ language standard
// (e.g. "-std=c++17", "-std=gnu++20"). Such flags must reach only the C++
// compiler.
func isCXXStdFlag(flag string) bool {
	return strings.HasPrefix(flag, "-std=") && strings.Contains(flag, "++")
}

// isCStdFlag reports whether the flag selects a C language standard
// (e.g. "-std=c11", "-std=gnu99"). Such flags must reach only the C compiler.
func isCStdFlag(flag string) bool {
	return strings.HasPrefix(flag, "-std=") && !strings.Contains(flag, "++")
}
