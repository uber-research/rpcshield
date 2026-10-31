package bazel

import (
	"bytes"
	"fmt"
	"go/parser"
	"go/printer"
	"go/token"
	iofs "io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/uber-research/rpcshield/go/common/utils"
	"go.uber.org/zap"
)

// This package provides a tool to rename internal directories in Go packages.
// It scans Go files for imports that reference `internal` directories and rewrites them.
// It also renames the directories on disk to avoid conflicts with the Go module system.
// The tool is designed to work with the Go build system and is particularly useful for Bazel users when using the go_path mode.

// fileRewriteInfo tracks which imports in a given file might need rewriting.
type fileRewriteInfo struct {
	// absFilePath is the absolute path of the file.
	absFilePath string
	// imports maps import paths to whether they contain any internal segments.
	// If an import contains internal, we'll need to rewrite it.
	imports map[string]bool // oldImportPath -> does it contain ANY internal? If so, we'll do a rewrite check.
}

// metrics counts basic metrics.
type metrics struct {
	filesTotal           int64
	filesWithInternal    int64
	filesRewritten       int64
	dirsRenamed          int64
	internalDirsDetected int64
}

// anFSRenamer implements the FSRenamer interface.
type anFSRenamer struct {
	//number of workers to use for parallel processing
	workers int
	// file system abstraction
	fs utils.FileSystem
	// logger for logging
	logger *zap.SugaredLogger
}

const _internalSubStr = "/internal/"
const _internalSuffix = "/internal"
const _internalDirName = "internal"

// defaultFSRenamer holds state and configuration for the renaming process.
type defaultFSRenamer struct {
	// Should be the absolute path to the GOPATH.
	gopath string
	// File system abstraction.
	fs utils.FileSystem
	// number of workers to use for parallel processing
	workers int
	// logger for logging
	logger *zap.SugaredLogger

	// state
	// internalImporters maps an internal directory to a set of importing files.
	// This is used to determine which internal directories need to be renamed.
	internalImporters map[string]map[string]struct{}
	// internalRenames maps an internal directory to its new name.
	// This is used to determine which directories need to be renamed.
	internalRenames map[string]string
	// filesToRewrite maps a file path to the rewrite info for that file.
	// This is used to determine which files need to be rewritten.
	filesToRewrite map[string]*fileRewriteInfo
	// metrics tracks various metrics during the renaming process.
	metrics             metrics
	internalRenameCount int
	m                   sync.Mutex
}

// NewFSRenamer creates a new instance.
func NewFSRenamer(fs utils.FileSystem, workers int, logger *zap.SugaredLogger) FSRenamer {
	return &anFSRenamer{
		workers: workers,
		logger:  logger,
		fs:      fs,
	}
}

// Rename performs the overall process of renaming internal directories.
// Since bazel build system allows internal directories to be imported directly, but the go list used in go_path mode does not,
// we need to rename internal directories and update references in .go files.
// The process is as follows:
// 1. Scan all .go files in the given root directory, collecting imports that reference `internal`.
// 2. Decide which internal directories must be renamed.
// 3. Rewrite .go files to update imports and references.
// 4. Physically rename internal directories on disk.
func (a *anFSRenamer) Rename(gopath, root string) error {

	br := defaultFSRenamer{
		gopath:            gopath,
		workers:           a.workers,
		fs:                a.fs,
		logger:            a.logger,
		internalImporters: make(map[string]map[string]struct{}),
		internalRenames:   make(map[string]string),
		filesToRewrite:    make(map[string]*fileRewriteInfo),
	}

	br.logger.Infof("Starting rename: Root=%v, GOPATH=%v\n", root, br.gopath)
	// 1. Scan .go files in parallel, collecting imports that reference `internal`
	if err := br.collectInternalImportingFiles(root); err != nil {
		return fmt.Errorf("walk error: %w", err)
	}

	// 2. Decide which internal dirs must be renamed.
	br.logger.Infof("Determining rename-needed internal directories...")
	br.filterPathsToRename()

	// 3. Rewrite .go files (imports + references)
	br.logger.Infof("Rewriting .go files as needed...")
	if err := br.rewrite(); err != nil {
		return fmt.Errorf("rewrite error: %w", err)
	}

	// 4. Physically rename internal directories on disk
	br.logger.Infof("Renaming directories on disk...")
	if err := br.renameInternalDirs(); err != nil {
		return fmt.Errorf("rename error: %w", err)
	}

	br.logger.Infow("Renamer", "total_files", br.metrics.filesTotal, "files_with_internal", br.metrics.filesWithInternal,
		"files_rewritten", br.metrics.filesRewritten, "dirs_renamed", br.metrics.dirsRenamed,
		"internal_dirs_detected", br.metrics.internalDirsDetected)

	return nil
}

// Walk files, parse imports, detect all `internal` segments.
func (br *defaultFSRenamer) collectInternalImportingFiles(root string) error {
	var goFiles []string
	err := br.fs.WalkDir(root, func(path string, d iofs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			goFiles = append(goFiles, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	br.logger.Debugf("Found %d .go files under %q", len(goFiles), root)

	// Parse in parallel.
	numWorkers := br.workers
	var wg sync.WaitGroup
	fileChan := make(chan string)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range fileChan {
				br.parseFileForInternalImports(f)
			}
		}()
	}

	for _, f := range goFiles {
		fileChan <- f
	}
	close(fileChan)
	wg.Wait()

	return nil
}

// importPathContainsInternal returns true if the import path contains "/internal/" or ends with "/internal".
func importPathContainsInternal(path string) bool {
	return strings.Contains(path, _internalSubStr) || strings.HasSuffix(path, _internalSuffix)
}

// parseFileForInternalImports scans a .go file for imports that reference `internal`.
// If any are found, it records the file for rewriting.
func (br *defaultFSRenamer) parseFileForInternalImports(filePath string) {
	atomic.AddInt64(&br.metrics.filesTotal, 1)

	src, err := br.fs.ReadFile(filePath)
	if err != nil {
		br.logger.Warnf("Could not read %q: %v", filePath, err)
		return
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, src, parser.AllErrors)
	if err != nil {
		br.logger.Warnf("Parse error in %q: %v", filePath, err)
		return
	}

	rewriteInfo := &fileRewriteInfo{
		absFilePath: filePath, // for debugging
		imports:     make(map[string]bool),
	}
	importingDirAbs, _ := br.fs.Abs(filepath.Dir(filePath))

	foundAny := false

	for _, imp := range f.Imports {
		pathVal := strings.Trim(imp.Path.Value, `"`)
		// Quick skip if no "internal" imports.
		if !importPathContainsInternal(pathVal) {
			continue
		}

		// Map the import like "example.internal/a/internal/b" to an absolute path like:
		// "/path/to/gopath/src/example.internal/a/internal/b"
		absImportPath := br.mapImportToDiskPath(pathVal)
		if absImportPath == "" {
			continue
		}

		// Find all internal directories in the path.
		// For example, if the path is "/path/to/gopath/src/example.internal/a/internal/b/internal/d
		// we would find "/path/to/gopath/src/example.internal/a/internal" and "/path/to/gopath/src/example.internal/a/internal/b/internal"
		subInternals := br.findAllInternalDirsInPath(absImportPath)
		if len(subInternals) == 0 {
			continue
		}

		foundAny = true
		rewriteInfo.imports[pathVal] = true

		br.m.Lock()
		for _, subDir := range subInternals {

			// if /go/path/src/a/b/c.go imports /go/path/src/a/internal/d/internal, we record:
			// br.internalImporters["/go/path/src/a/internal/d/internal"] = map["/go/path/src/a/b/c.go"]{}
			// and
			// br.internalImporters["/go/path/src/a/internal"] = map["/go/path/src/a/b/c.go"]{}

			br.logger.Debugf("Import %q in %q references internal %q\n", pathVal, filePath, subDir)
			m, ok := br.internalImporters[subDir]
			if !ok {
				m = make(map[string]struct{})
				br.internalImporters[subDir] = m
				atomic.AddInt64(&br.metrics.internalDirsDetected, 1)
			}
			m[importingDirAbs] = struct{}{}
		}
		br.m.Unlock()
	}

	if foundAny {
		atomic.AddInt64(&br.metrics.filesWithInternal, 1)
		br.m.Lock()
		br.filesToRewrite[filePath] = rewriteInfo
		br.m.Unlock()
	}
}

func isStandardLibraryOrRelativeImport(path string) bool {
	return !strings.Contains(path, ".") && !strings.HasPrefix(path, "./") && !strings.HasPrefix(path, "../")
}

// mapImportToDiskPath maps a user import to an absolute path under GOPATH.
func (br *defaultFSRenamer) mapImportToDiskPath(importPath string) string {
	importPath = strings.TrimSpace(importPath)
	full := filepath.Join(br.gopath, "src", importPath)
	abs, err := br.fs.Abs(full)
	if err != nil {
		return ""
	}
	// A dot-free import path normally means the standard library, but Bazel codegen also
	// produces dot-free import paths that get lifted into the GOPATH (e.g. gen/..., thriftrw/...,
	// gogoproto/... and similar generated trees). Treating those as standard library hides their
	// "internal" directories from the renamer, and the lifted tree then fails to load with
	// "use of internal package ... not allowed". The two are easy to tell apart on disk: the
	// standard library lives in GOROOT and never has a directory under GOPATH/src.
	if isStandardLibraryOrRelativeImport(importPath) && !br.isDirInGoPath(abs) {
		return ""
	}
	return abs
}

// isDirInGoPath reports whether absPath is an existing directory in the lifted GOPATH.
func (br *defaultFSRenamer) isDirInGoPath(absPath string) bool {
	fi, err := br.fs.Stat(absPath)
	return err == nil && fi.IsDir()
}

// findAllInternalDirsInPath returns a slice of absolute directories (each ending in "internal")
// for every occurrence of "internal" in absPath.
func (br *defaultFSRenamer) findAllInternalDirsInPath(absPath string) []string {
	pathSlashed := filepath.ToSlash(absPath)
	parts := strings.Split(pathSlashed, "/")
	gopathPrefix := filepath.ToSlash(filepath.Join(br.gopath, "src"))

	var results []string
	for i := 0; i < len(parts); i++ {
		if parts[i] == "internal" {
			sub := filepath.Join(parts[:i+1]...)
			// Since the path is split, we need to re-add the slashes.
			if strings.HasPrefix(absPath, "/") && !strings.HasPrefix(sub, "/") {
				sub = "/" + sub
			}
			sub = filepath.Clean(sub)
			// One more check to ensure we're not in the GOPATH.
			if strings.HasPrefix(sub, gopathPrefix) {
				results = append(results, sub)
			}
		}
	}
	return results
}

// filterPathsToRename determines which internal directories need to be renamed.
// It does this by checking if any importers are outside the internal directory's boundary.
// SPEC: https://go.dev/doc/go1.4#internalpackages
// If an internal directory is imported by a package outside its boundary, it must be renamed.
// For example, if "example.internal/a/internal" is imported by "example.internal/b",
// we must rename "example.internal/a/internal" to "example.internal/a/internalx1".
// For nested internals like "example.internal/a/internal/b/internal", we must apply the same rule innermost first.
// In this example, if "example.internal/a/internal/b/internal" is imported by "example.internal/a/internal/c",
// we must rename "example.internal/a/internal/b/internal" to "example.internal/a/internalx1", but no rename is needed for "example.internal/a/internal".
// However, if "example.internal/a/internal/b/internal" is imported by "example.internal/p",
// we must rename "example.internal/a/internal" to "example.internal/a/internalx2/b/internalx1".
func (br *defaultFSRenamer) filterPathsToRename() {
	br.m.Lock()
	defer br.m.Unlock()

	for absInternalDir, importers := range br.internalImporters {
		boundary := filepath.Dir(absInternalDir)

		renameNeeded := false
		for impDir := range importers {
			if !br.isSubdirOf(impDir, boundary) {
				renameNeeded = true
				break
			}
		}
		if renameNeeded {
			newName := br.generateNewInternalNameLocked()
			br.internalRenames[absInternalDir] = newName
			br.logger.Infof("Marking directory for rename: %q => %q\n", absInternalDir, newName)
		}
	}
}

// generateNewInternalNameLocked is a thread-safe way to generate a new internal name.
// It is called with the mutex held.
func (br *defaultFSRenamer) generateNewInternalNameLocked() string {
	name := fmt.Sprintf("internalx%d", br.internalRenameCount)
	br.internalRenameCount++
	return name
}

// isSubdirOf reports whether path is inside or the same as parent.
func (br *defaultFSRenamer) isSubdirOf(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// rewrite rewrites all files that need it.
func (br *defaultFSRenamer) rewrite() error {
	for filePath, info := range br.filesToRewrite {
		if err := br.rewriteOneFile(filePath, info); err != nil {
			return fmt.Errorf("rewriteOneFile(%s): %w", filePath, err)
		}
	}
	return nil
}

// rewriteOneFile rewrites a single file.
// It updates the import paths in the file to reflect the new internal directory names.
func (br *defaultFSRenamer) rewriteOneFile(filePath string, info *fileRewriteInfo) error {
	src, err := br.fs.ReadFile(filePath)
	if err != nil {
		br.logger.Warnf("Could not read file for rewrite %q: %v", filePath, err)
		return err
	}

	fset := token.NewFileSet()
	fileAst, err := parser.ParseFile(fset, filePath, src, parser.AllErrors|parser.ParseComments)
	if err != nil {
		return nil
	}

	didChange := false

	for _, imp := range fileAst.Imports {
		oldPath := strings.Trim(imp.Path.Value, `"`)
		if !info.imports[oldPath] {
			continue
		}
		newImportPath := br.rewriteImportPath(oldPath)
		if newImportPath != oldPath {
			br.logger.Debugf("Rewriting import in %q: %q => %q\n", filePath, oldPath, newImportPath)
			imp.Path.Value = fmt.Sprintf("%q", newImportPath)
			didChange = true
		}
	}

	if !didChange {
		return nil
	}

	// Write the file back.
	// Make the file writable first since we may have read-only files.
	err = br.makeFileWritable(filePath)
	if err != nil {
		br.logger.Warnf("Could not make file writable %q: %v", filePath, err)
		return err
	}

	var buf bytes.Buffer
	cfg := printer.Config{Mode: printer.TabIndent, Tabwidth: 8}
	if err := cfg.Fprint(&buf, fset, fileAst); err != nil {
		return err
	}
	if err := br.fs.WriteFile(filePath, buf.Bytes(), 0644); err != nil {
		return err
	}

	atomic.AddInt64(&br.metrics.filesRewritten, 1)
	br.logger.Infof("Rewrote file %q", filePath)
	return nil
}

// rewriteImportPath replaces each "internal" segment in oldImportPath for which we have a rename.
// The lookup is done using the original import path segments, so that nested "internal" directories
// are correctly recognized and renamed.
func (br *defaultFSRenamer) rewriteImportPath(oldImportPath string) string {
	origSegments := strings.Split(oldImportPath, "/")
	newSegments := make([]string, len(origSegments))
	copy(newSegments, origSegments)
	changed := false

	for i, seg := range origSegments {
		if seg == _internalDirName {
			// Always use the original segments to compute the lookup key.
			partialImport := strings.Join(origSegments[:i+1], "/")
			absPartial := br.mapImportToDiskPath(partialImport)
			if newName, ok := br.internalRenames[absPartial]; ok {
				newSegments[i] = newName
				changed = true
			}
		}
	}
	if !changed {
		return oldImportPath
	}
	return strings.Join(newSegments, "/")
}

func (br *defaultFSRenamer) makeFileWritable(path string) error {
	dir := filepath.Dir(path)
	if err := br.fs.Chmod(dir, 0755); err != nil {
		return err
	}
	return br.fs.Chmod(path, 0644)
}

// renameInternalDirs renames internal directories on disk.
// It renames directories in decreasing order of length to avoid renaming parent directories first.
func (br *defaultFSRenamer) renameInternalDirs() error {
	var keys []string
	for k := range br.internalRenames {
		// Check if the directory exists via Stat.
		if _, err := br.fs.Stat(k); err != nil {
			return fmt.Errorf("could not stat %q: %w", k, err)
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})

	for _, oldPath := range keys {
		newName := br.internalRenames[oldPath]

		dirToRename := oldPath
		base := filepath.Base(dirToRename)
		// if the base is not "internal", something is wrong.
		// Log an error and skip.

		if base != _internalDirName {
			br.logger.Errorf("Expected base to be 'internal' but got %q", base)
			continue
		}

		parentDir := filepath.Dir(dirToRename)
		newDir := filepath.Join(parentDir, newName)
		_ = br.fs.Chmod(parentDir, 0755)

		br.logger.Infof("Renaming directory %q => %q", dirToRename, newDir)
		if err := br.fs.Rename(dirToRename, newDir); err != nil {
			return err
		}
		atomic.AddInt64(&br.metrics.dirsRenamed, 1)
	}
	return nil
}
