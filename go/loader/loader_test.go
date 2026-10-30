package loader

import (
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLoadSSA (the monorepo original) is intentionally not ported here: it loads a real service
// package (cff-demo) that only exists inside a monorepo via a Bazel data dependency, so it
// isn't portable to a standalone build. LoadSSAWithGoPath itself is still exercised indirectly by
// TestFailure below.

func TestLoadSSA_Error(t *testing.T) {
	t.Parallel()

	// Test that LoadSSAWithGoPath correctly propagates errors from LoadWithGoPath
	prog, pkg, allPkgs, err := LoadSSAWithGoPath(
		DefaultRootDirName,
		[]string{"doesnotexist"},
		"/a/non/existent/path",
	)
	require.Error(t, err, "should return error for invalid path")
	require.Nil(t, prog, "program should be nil when error occurs")
	require.Nil(t, pkg, "package should be nil when error occurs")
	require.Nil(t, allPkgs, "all packages should be nil when error occurs")
}

func TestLoadSimplePackage(t *testing.T) {
	t.Parallel()

	root := "testdata"
	pkg, err := LoadSimplePackage(filepath.Join(root, "src", "example.internal", "simplepkg"), root, nil /* filter */)
	require.NoError(t, err)
	require.NotEmpty(t, pkg)
	require.Equal(t, "example.internal/simplepkg", pkg.PkgPath)
	// AST information must be there.
	require.NotEmpty(t, pkg.Dir)
	require.NotEmpty(t, pkg.Fset)
	require.NotEmpty(t, pkg.Files)

	// Uses and Defs for local variables must have been established.
	require.NotEmpty(t, pkg.TypesInfo.Uses)
	require.NotEmpty(t, pkg.TypesInfo.Defs)
	// Even though import resolution is not done, the import slice must have been populated
	// (although with incomplete packages).
	require.NotEmpty(t, pkg.Types.Imports())
	require.NotEmpty(t, pkg.Types)
}

func TestLoadSimplePackage_Ignore(t *testing.T) {
	t.Parallel()

	root := "testdata"
	pkg, err := LoadSimplePackage(
		filepath.Join(root, "src", "example.internal", "simplepkg"), root,
		func(entry fs.DirEntry) bool { return entry.Name() != "ignore.go" },
	)
	require.NoError(t, err)
	require.NotEmpty(t, pkg)
	var collectedFileNames []string
	pkg.Fset.Iterate(func(f *token.File) bool { collectedFileNames = append(collectedFileNames, f.Name()); return true })
	require.NotContains(t, collectedFileNames, "testdata/src/example.internal/simplepkg/ignore.go")
}

func TestLoadSimplePackage_NoSuchDir(t *testing.T) {
	t.Parallel()

	root := "testdata"
	pkg, err := LoadSimplePackage(filepath.Join(root, "src", "example.internal", "nosuchdir"), root, nil /* filter */)
	require.Error(t, err)
	require.Empty(t, pkg)
}

// TestEnv tests the env function with various inputs.
func TestEnv(t *testing.T) {
	t.Run("NoCdeps", func(t *testing.T) {
		goPath := "/test/gopath"
		cdeps := []string{}
		envVars := env(goPath, cdeps)

		if !contains(envVars, "GO111MODULE=off") {
			t.Errorf("expected GO111MODULE=off in environment, got %+v", envVars)
		}
		if !contains(envVars, "GOPATH="+goPath) {
			t.Errorf("expected GOPATH=%s in environment, got %+v", goPath, envVars)
		}
		if containsPrefix(envVars, "CGO_ENABLED=") {
			t.Errorf("did not expect CGO_ENABLED to be set for empty cdeps, got %+v", envVars)
		}
		if containsPrefix(envVars, "CGO_CFLAGS=") {
			t.Errorf("did not expect CGO_CFLAGS to be set for empty cdeps, got %+v", envVars)
		}
		if containsPrefix(envVars, "CGO_CXXFLAGS=") {
			t.Errorf("did not expect CGO_CXXFLAGS to be set for empty cdeps, got %+v", envVars)
		}
		if containsPrefix(envVars, "CGO_CPPFLAGS=") {
			t.Errorf("did not expect CGO_CPPFLAGS to be set for empty cdeps, got %+v", envVars)
		}
	})

	t.Run("WithCdeps", func(t *testing.T) {
		goPath := "/another/gopath"
		cdeps := []string{"-I/usr/include", "-I/custom/include"}
		envVars := env(goPath, cdeps)

		if !contains(envVars, "GO111MODULE=off") {
			t.Errorf("expected GO111MODULE=off in environment, got %+v", envVars)
		}
		if !contains(envVars, "GOPATH="+goPath) {
			t.Errorf("expected GOPATH=%s in environment, got %+v", goPath, envVars)
		}
		if !contains(envVars, "CGO_ENABLED=1") {
			t.Errorf("expected CGO_ENABLED=1 in environment for non-empty cdeps, got %+v", envVars)
		}

		// The include paths must be mirrored into the C, C++, and preprocessor flags so
		// that cgo can resolve headers regardless of the embedded source language (.c
		// uses CGO_CFLAGS, .cc uses CGO_CXXFLAGS, both preprocess with CGO_CPPFLAGS).
		joined := strings.Join(cdeps, " ")
		for _, key := range []string{"CGO_CFLAGS", "CGO_CXXFLAGS", "CGO_CPPFLAGS"} {
			expected := key + "=" + joined
			if !contains(envVars, expected) {
				t.Errorf("expected %s in environment, got %+v", expected, envVars)
			}
		}
	})

	// A C++ language-standard flag must reach only the C++ compiler. If it leaked
	// into CGO_CFLAGS or the shared CGO_CPPFLAGS, gcc would reject every .c cgo
	// source ("-std=c++NN is valid for C++ but not for C").
	t.Run("CXXStdFlagRoutedToCXXOnly", func(t *testing.T) {
		cdeps := []string{"-I/inc", "-std=c++17"}
		envVars := env("/gp", cdeps)

		if v, _ := envValue(envVars, "CGO_CXXFLAGS"); v != "-I/inc -std=c++17" {
			t.Errorf("CGO_CXXFLAGS = %q, want %q", v, "-I/inc -std=c++17")
		}
		if v, _ := envValue(envVars, "CGO_CFLAGS"); v != "-I/inc" {
			t.Errorf("CGO_CFLAGS = %q, want %q (C++ std must not leak to C)", v, "-I/inc")
		}
		if v, _ := envValue(envVars, "CGO_CPPFLAGS"); v != "-I/inc" {
			t.Errorf("CGO_CPPFLAGS = %q, want %q (C++ std must not leak to shared preprocessor)", v, "-I/inc")
		}
	})

	// A C language-standard flag must reach only the C compiler.
	t.Run("CStdFlagRoutedToCOnly", func(t *testing.T) {
		cdeps := []string{"-I/inc", "-std=c11"}
		envVars := env("/gp", cdeps)

		if v, _ := envValue(envVars, "CGO_CFLAGS"); v != "-I/inc -std=c11" {
			t.Errorf("CGO_CFLAGS = %q, want %q", v, "-I/inc -std=c11")
		}
		if v, _ := envValue(envVars, "CGO_CXXFLAGS"); v != "-I/inc" {
			t.Errorf("CGO_CXXFLAGS = %q, want %q (C std must not leak to C++)", v, "-I/inc")
		}
		if v, _ := envValue(envVars, "CGO_CPPFLAGS"); v != "-I/inc" {
			t.Errorf("CGO_CPPFLAGS = %q, want %q", v, "-I/inc")
		}
	})
}

func TestFailure(t *testing.T) {
	entrypkg, allPkg, err := LoadWithGoPath(DefaultRootDirName, []string{"doesnotexist"}, "/a/non/existent/path")
	require.Error(t, err)
	require.Nil(t, entrypkg)
	require.Empty(t, allPkg)
}

// contains checks if a slice of strings has an exact match for a given item.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// containsPrefix checks if any item in a slice of strings has the specified prefix.
func containsPrefix(slice []string, prefix string) bool {
	for _, s := range slice {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// envValue returns the value of the first "KEY=value" entry matching key.
func envValue(slice []string, key string) (string, bool) {
	for _, s := range slice {
		if strings.HasPrefix(s, key+"=") {
			return strings.TrimPrefix(s, key+"="), true
		}
	}
	return "", false
}
