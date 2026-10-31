package bazel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/common/utils"
	"go.uber.org/zap/zaptest"
)

// TestMapImportToDiskPathDotFreeCodegen covers import paths whose every segment is dot-free.
// Those look exactly like standard library imports, but Bazel codegen can emit such paths
// (for example generated protobuf or Thrift packages) and lift them into the GOPATH. They must
// be mapped to disk so that the renamer can see their "internal" directories.
func TestMapImportToDiskPathDotFreeCodegen(t *testing.T) {
	t.Parallel()

	gopath := t.TempDir()
	codegenPkg := "gen/translation/storage/internal/translation/jobs"
	require.NoError(t, os.MkdirAll(filepath.Join(gopath, "src", codegenPkg), 0755))

	renamer := defaultFSRenamer{
		gopath:            gopath,
		fs:                utils.OSFileSystem{},
		workers:           1,
		logger:            zaptest.NewLogger(t).Sugar(),
		internalImporters: make(map[string]map[string]struct{}),
		internalRenames:   make(map[string]string),
		filesToRewrite:    make(map[string]*fileRewriteInfo),
	}

	tests := []struct {
		name       string
		importPath string
		want       string
	}{
		{
			name:       "dot-free codegen package present in GOPATH",
			importPath: codegenPkg,
			want:       filepath.Join(gopath, "src", codegenPkg),
		},
		{
			name:       "standard library internal package is not in GOPATH",
			importPath: "internal/abi",
			want:       "",
		},
		{
			name:       "standard library package is not in GOPATH",
			importPath: "fmt",
			want:       "",
		},
		{
			name:       "dotted package is mapped without touching disk",
			importPath: "example.com/i18n/translation_storage/handler",
			want:       filepath.Join(gopath, "src", "example.com/i18n/translation_storage/handler"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, renamer.mapImportToDiskPath(tt.importPath))
		})
	}
}
