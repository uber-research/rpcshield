package bazel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/uber-research/rpcshield/go/common/utils"
)

// Below are the structures for parsing the JSON output of `bazel cquery --output=jsonproto`.
// For example, following is the output of the command: `bazel cquery "@icu4c//:icu4c" --output=jsonproto`
//
// {
//  "results": [{
//    "target": {
//      "type": "RULE",
//      "rule": {
//        "name": "@icu4c//:icu4c",
//        "ruleClass": "cc_library",
//        "location": "/home/user/.cache/bazel/_bazel_smahajan/b97476d719d716accead0f2d5b93104f/external/icu4c/BUILD.bazel:269:11",
//        "attribute": [
//          ...
//          {
//          "name": "copts",
//          "type": "STRING_LIST",
//          "stringListValue": ["-fno-exceptions", "-I.//source/common", "-I.//source/i18n", "-I.//source/io", "-I.//source/tools/ctestfw", "-I.//source/tools/toolutil", "-Wno-deprecated-declarations", "-Wno-sign-compare", "-O2"],
//          "explicitlySpecified": true,
//          "nodep": false
//        },
//        ...
//        ],
//        ...
// }

// CqueryResponse is the top-level structure, containing a list of Result objects.
type CqueryResponse struct {
	Results []Result `json:"results"`
}

// Result contains the target information.
type Result struct {
	Target Target `json:"target"`
}

// Target contains the rule information.
type Target struct {
	Type string `json:"type"`
	Rule Rule   `json:"rule"`
}

// Rule contains the rule information.
type Rule struct {
	Name       string      `json:"name"`
	RuleClass  string      `json:"ruleClass"`
	Location   string      `json:"location"`
	Attributes []Attribute `json:"attribute"`
}

// Attribute contains the attribute information.
type Attribute struct {
	Name                string   `json:"name"`
	Type                string   `json:"type"`
	StringListValue     []string `json:"stringListValue"`
	StringValue         string   `json:"stringValue"`
	ExplicitlySpecified bool     `json:"explicitlySpecified"`
}

// processCGo processes the C++ dependencies of the target and returns the `-I` flags, if any. The function handles the following CGo cases:
//
//	(1) Dependencies listed as `cdeps` in the go_library rule.
//		Example:
//			go_library(
//				name = "go_default_library",
//				srcs = [
//					"bridge.cpp",
//					"bridge.h",
//					"message_formatter.go",
//					...
//				],
//				cdeps = ["@icu4c//:icu4c"],
//				cgo = True,
//				...
//			)
//
//	 2. Dependencies listed as raw `cc_library` rules.
//	    Example:
//			cc_library(
//			name = "ucrypto",
//			srcs = glob([
//	    		"*.cpp",
//	    		...
//			]),
//			hdrs = glob([
//	    		"*.h",
//	    		...
//			]),
//			copts = [
//	    		"-x c++",
//	    		"-fno-sanitize=undefined",
//			],
//			visibility = ["//visibility:public"],
//			deps = [
//	    		"@glog",
//	    		"@libsodium",
//	    		"@openssl//:ssl",
//			],
//		)
// 3. An internal service depends on an external Go_lib which further depends on a cc_library
// Redactor --> @com_github_openvenues_gopostal//parser:parser --> @libpostal//:libpostal
// @com_github_openvenues_gopostal//parser:parser:
// go_library(
//     name = "parser",
//     srcs = ["parser.go"],
//     cdeps = ["@libpostal"],
//     cgo = True,
//     data = [
//        ...
//     ],
//     importpath = "github.com/openvenues/gopostal/parser",
//     visibility = ["//visibility:public"],
// )
// @libpostal//:libpostal:
// cc_library(
//     name = "libpostal",
//     srcs = ["src/" + src for src in SRCS] + glob(["src/**/*.h"]),
//     hdrs = ["src/libpostal.h"],
//     include_prefix = "libpostal",
//     visibility = ["//visibility:public"],
//     ...
// )

func (br *gopathWrapper) processCGo(runner utils.Runner, target string, gopathRoot string) ([]string, error) {
	// Fetch all cc_library (C++) dependencies (direct and transitive) of target
	br.Logger.Infow("processCGo", "target", target)

	// --bes_backend= overrides any .bazelrc BEP endpoint for these metadata queries: they
	// execute zero build actions, so a flaky BEP endpoint would otherwise make bazel exit
	// non-zero after streaming a complete, valid response to stdout -- which ExecCommand
	// discards. Disabling BEP here decouples the query from BEP-endpoint health.
	ccOut, _, err := utils.ExecCommand(runner, br.BazelPath, "query", "--bes_backend=", "--output=label", fmt.Sprintf("kind(cc_library, deps(%s))", target))
	if err != nil {
		return nil, err
	}
	ccLibs := strings.Split(strings.TrimSpace(string(ccOut)), "\n")
	// Handle C/C++ library built as `go_library`
	ccOutGoDeps, _, err := utils.ExecCommand(
		runner,
		br.BazelPath,
		"query",
		"--output=label",
		fmt.Sprintf(`attr("cgo", 1, kind("go_library", deps("%s")))`, target),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get attribute cgo output for: %w", err)
	}
	goCLibs := strings.Split(strings.TrimSpace(string(ccOutGoDeps)), "\n")

	// Iterate over each of the cc_library dependencies and extract the -I flags from `copts`.
	iFlagsSlice := make([]string, 0, len(ccLibs))
	iFlagDedup := make(map[string]bool)
	clibFilesMap := make(map[string][]string)
	clibSrcPathMap := make(map[string]string)
	if len(goCLibs) > 0 {
		ccLibs1, localClibFilesMap, localclibLocationPath, err := br.getDependentCLibs(runner, goCLibs)
		if err != nil {
			return nil, fmt.Errorf("failed to get lower c lib for: %w", err)
		}
		clibFilesMap = localClibFilesMap
		clibSrcPathMap = localclibLocationPath
		ccLibs = append(ccLibs, ccLibs1...)
	}

	// Iterate over each of the cc_library dependencies and extract the -I flags from `copts`.
	for _, ccLib := range ccLibs {
		if len(ccLib) == 0 {
			continue
		}
		// Retrieve detailed build information about the cc_library target in JSON format.
		resp, err := br.configQuery(runner, ccLib)
		if err != nil {
			return nil, fmt.Errorf("failed to get cquery output for %s: %w", ccLib, err)
		}
		err = br.preProcessCgoPkgConfig(runner, ccLib, gopathRoot, clibFilesMap, clibSrcPathMap)
		if err != nil {
			return nil, fmt.Errorf("failed to preprocess cgo pkg-config for %s: %w", ccLib, err)
		}

		err = br.processCqueryResponse(runner, resp, &iFlagsSlice, iFlagDedup, gopathRoot)
		if err != nil {
			return nil, fmt.Errorf("failed to process cquery response for %s: %w", ccLib, err)
		}
	}
	return iFlagsSlice, nil
}

// preProcessCgoPkgConfig Remove cgo pkg-config lines from the copied source files
//	that go file containing cgo pkg-config which requires a c library
// Example:
// #cgo pkg-config: libpostal
// #include <libpostal/libpostal.h>
// #include <stdlib.h>
// import "C"
//
// Expected output:
// #include <libpostal/libpostal.h>
// #include <stdlib.h>
// import "C"

// Bazel file for a go-> c library
// go_library(
//
//	name = "parser",
//	srcs = ["parser.go"],
//	cdeps = ["@libpostal"],
//	cgo = True,
//	data = [
//	   ...
//	],
//	importpath = "github.com/openvenues/gopostal/parser",
//	visibility = ["//visibility:public"],
//
// )
func (br *gopathWrapper) preProcessCgoPkgConfig(runner utils.Runner, ccLib, gopathRoot string, clibFilesMap map[string][]string, clibSrcPathMap map[string]string) error {
	srcsGoFiles, _ := clibFilesMap[ccLib]
	clibSrcPath := clibSrcPathMap[ccLib]
	// Remove cgo pkg-config lines.
	// Get `importpath` From Bazel at clibSrcPath
	for _, srcGoFile := range srcsGoFiles {
		// Sometimes the Go target could include non-Go files as sources so we skip them.
		if !strings.HasSuffix(srcGoFile, ".go") {
			continue
		}
		bazelFile := filepath.Join(clibSrcPath, "BUILD.bazel")
		importPath, err := getImportPathFromBazelFile(bazelFile)
		if err != nil {
			return fmt.Errorf("failed to get import path from bazel file: %w", err)
		}
		srcGoFilePath := filepath.Join(gopathRoot, "src", importPath)
		srcGoFiles := strings.Split(srcGoFile, ":")
		if len(srcGoFiles) > 1 {
			srcGoFile = srcGoFiles[1]
		} else {
			return fmt.Errorf("failed to get srcGoFile from srcGoFiles: %w", err)
		}
		srcGoFile = filepath.Join(srcGoFilePath, srcGoFile)
		// br.Logger.Debugw("clibSrcPath", "clibSrcPath", clibSrcPath)
		// br.Logger.Debugw("importPath", "importPath", importPath)
		// br.Logger.Debugw("srcGoFilePath", "srcGoFilePath", srcGoFilePath)
		if _, _, err := utils.ExecCommand(runner, "chmod", "-R", "777", srcGoFile); err != nil {
			return fmt.Errorf("failed to make %q writable: %w", srcGoFile, err)
		}
		err = removeCgoPkgConfigLinesFromFile(srcGoFile)
		if err != nil {
			return fmt.Errorf("failed to remove cgo pkg-config lines from file: %w", err)
		}
	}
	return nil
}

func (br *gopathWrapper) getDependentCLibs(runner utils.Runner, goCLibs []string) ([]string, map[string][]string, map[string]string, error) {
	// Get all cc_library and corresponding source files and location path.
	allclibs := make([]string, 0)
	clibFilesMap := make(map[string][]string)
	clibLocationPath := make(map[string]string)
	for _, goCLib := range goCLibs {
		if goCLib == "" {
			continue
		}
		resp, err := br.configQuery(runner, goCLib)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get cquery output for %s: %w", goCLib, err)
		}
		clibs, localclibFilesMap, localclibLocationPath, err := br.cqueryMine(runner, resp)
		mergeMaps(clibFilesMap, localclibFilesMap)
		mergeMaps(clibLocationPath, localclibLocationPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get cquery output for %s: %w", goCLib, err)
		}
		allclibs = append(allclibs, clibs...)
	}
	return allclibs, clibFilesMap, clibLocationPath, nil
}

func mergeMaps[K comparable, V any](dst, src map[K]V) {
	for k, v := range src {
		dst[k] = v
	}
}

// cqueryMine explores cdep of the current go_library target
func (br *gopathWrapper) cqueryMine(runner utils.Runner, resp CqueryResponse) ([]string, map[string][]string, map[string]string, error) {
	clibs := make([]string, 0)
	clibSrcGoFiles := make(map[string][]string)
	clibLocationPath := make(map[string]string)

	for _, r := range resp.Results {
		rule := r.Target.Rule
		br.Logger.Debugw("explore go lib -> c lib deps", "golib", rule.Name)
		for _, attr := range rule.Attributes {
			if isCdeps(attr) {
				for _, c := range attr.StringListValue {
					br.Logger.Debugw("explore go lib -> c lib deps", "clib", c)
					clibs = append(clibs, c)
					clibSrcGoFiles[c] = []string{}
				}
			}
		}
		if len(clibs) == 0 {
			continue
		}
		for _, attr := range rule.Attributes {
			if srcGo(attr) {
				c := clibs[len(clibs)-1] // always the last cdep
				for _, s := range attr.StringListValue {
					clibSrcGoFiles[c] = append(clibSrcGoFiles[c], s)
				}
			}
		}

		clibLocationPath[clibs[len(clibs)-1]] = filepath.Dir(rule.Location)
	}
	return clibs, clibSrcGoFiles, clibLocationPath, nil
}

func (br *gopathWrapper) processCCLibrary(runner utils.Runner, rule Rule, libLocationPath string, iFlagsSlice *[]string, iFlagDedup map[string]bool, gopathRoot string) error {
	br.Logger.Debugw("process cquery response cc_library", "clibName", rule.Name)
	// To avoid order of the attributes, iterate N times.
	for _, attr := range rule.Attributes {
		// Extract the `-I` flags from the `copts` field. -I` flags specify `include` directories for the compiler.
		// They tell the compiler where to look for header files when processing `#include` directives.
		// `bazel build --remote_download_all` downloads the required files, but we need to include the `-I` flags
		// to point to the downloaded files in GOPATH to load the packages correctly.
		if isCopts(attr) {
			for _, c := range attr.StringListValue {
				if normalizedFlag, ok := getNormalizedIFlag(libLocationPath, c); ok {
					if _, ok := iFlagDedup[normalizedFlag]; !ok {
						*iFlagsSlice = append(*iFlagsSlice, normalizedFlag)
						iFlagDedup[normalizedFlag] = true
					}
				} else if isStdCopt(c) {
					// Preserve the C/C++ language-standard flag (e.g. `-std=c++17`).
					// Unlike include paths, nothing else reproduces it for the
					// non-Bazel cgo build, so it must be forwarded to cgo or C++
					// sources fail to compile on toolchains whose default standard
					// predates the one the library requires. The loader routes it
					// to the correct compiler based on language.
					if _, ok := iFlagDedup[c]; !ok {
						*iFlagsSlice = append(*iFlagsSlice, c)
						iFlagDedup[c] = true
					}
				}
			}
		}
	}
	var includePrefix string
	for _, attr := range rule.Attributes {
		if isIncPrefix(attr) {
			includePrefix = attr.StringValue
		}
	}

	// Handle internal CGO-cc_library
	if strings.HasPrefix(libLocationPath, br.Workspace) {
		for _, attr := range rule.Attributes {
			// Copy the raw cc_library source/header files explicitly to the lifted path location.
			// This is required because `bazel build --remote_download_all` does not download the raw cc_library files.
			if isRawSrcsOrHdrs(attr) {
				depPath, err := br.copySrcHdrFiles(runner, libLocationPath, gopathRoot, includePrefix, attr.StringListValue)
				if err != nil {
					return fmt.Errorf("copySrcHdrFiles fail: %w", err)
				}
				if len(depPath) > 0 {
					normDepPath := fmt.Sprintf("-I%s", depPath)
					if _, ok := iFlagDedup[normDepPath]; !ok {
						*iFlagsSlice = append(*iFlagsSlice, normDepPath)
						iFlagDedup[normDepPath] = true
					}
				}
			}
		}
	} else {
		//Handle external CGO-cc_library
		err := br.extractBazelGenIncPath(runner, rule, iFlagsSlice, iFlagDedup, gopathRoot, includePrefix)
		if err != nil {
			return fmt.Errorf("failed to extract bazel gen inc path: %w", err)
		}
	}
	return nil
}

func (br *gopathWrapper) extractBazelGenIncPath(runner utils.Runner, rule Rule, iFlagsSlice *[]string, iFlagDedup map[string]bool, gopathRoot, includePrefix string) error {
	// To generate necessary header files via parsing bazel build output
	// 1. build external target
	_, _, err := utils.ExecCommand(runner, br.BazelPath, "build", rule.Name)
	if err != nil {
		return err
	}
	// 2. parse bazel build output
	// The output is a list of files generated by the build
	// Example: {bazel-out/k8-fastbuild/bin/external/libpostal/libscanner.a\nbazel-out/k8-fastbuild/bin/external/libpostal/libscanner.so\n}
	outlist, _, err := utils.ExecCommand(runner, br.BazelPath, "cquery", "--bes_backend=", rule.Name, "--output=starlark",
		`--starlark:expr="\n".join([f.path for f in target.files.to_list()])`)
	if err != nil {
		return err
	}
	// 3. parse the output to retrieve the necessary include path
	genIncPath := make(map[string]int)
	genOutList := strings.Split(outlist, "\n")
	for _, out := range genOutList {
		if len(out) == 0 {
			continue
		}

		filepieces := strings.Split(out, "/")
		filename := filepieces[len(filepieces)-1]
		if strings.HasSuffix(filename, ".so") || strings.HasSuffix(filename, ".a") {
			genIncPath[filepath.Dir(out)] = 1 //if out contains .so or .a file, use its parent folder path.
		} else if !strings.Contains(filename, ".") {
			genIncPath[out] = 0 // if out is target, use the target path, all the files are in the target path.
		}
	}
	bazelOutPath, _, err := utils.ExecCommand(runner, br.BazelPath, "info", "output_path")
	if err != nil {
		return err
	}
	bazelOutPath = strings.TrimSpace(bazelOutPath)
	bazelOutPath = filepath.Dir(bazelOutPath)

	for incPath, isGen := range genIncPath {
		if isGen == 0 {
			normDepPath := fmt.Sprintf("-I%s", filepath.Join(bazelOutPath, incPath))
			if _, ok := iFlagDedup[normDepPath]; !ok {
				*iFlagsSlice = append(*iFlagsSlice, normDepPath)
				iFlagDedup[normDepPath] = true
			}
		} else {
			// Cmake or configure cc_library would generate synthetic include path.
			// Add include folder to the iFlagsSlice.
			entries, err := os.ReadDir(incPath)
			if err != nil {
				return err
			}

			var subdirs []string
			for _, entry := range entries {
				if entry.IsDir() && (strings.Contains(entry.Name(), "_virtual_includes") || strings.Contains(entry.Name(), "include")) {
					subdirs = append(subdirs, filepath.Join(incPath, entry.Name()))
				}
			}
			for _, subdir := range subdirs {
				normDepPath := fmt.Sprintf("-I%s", filepath.Join(bazelOutPath, subdir, includePrefix))
				if _, ok := iFlagDedup[normDepPath]; !ok {
					*iFlagsSlice = append(*iFlagsSlice, normDepPath)
					iFlagDedup[normDepPath] = true
				}
			}
		}
	}
	return nil
}

func (br *gopathWrapper) processCMake(runner utils.Runner, rule Rule, iFlagsSlice *[]string, iFlagDedup map[string]bool, gopathRoot string) error {
	br.Logger.Debugw("process cquery response using CMAKE", "clibName", rule.Name)
	var includePrefix string
	for _, attr := range rule.Attributes {
		if isIncPrefix(attr) {
			includePrefix = attr.StringValue
		}
	}
	err := br.extractBazelGenIncPath(runner, rule, iFlagsSlice, iFlagDedup, gopathRoot, includePrefix)
	if err != nil {
		return fmt.Errorf("failed to extract bazel gen inc path: %w", err)
	}
	return nil
}

func (br *gopathWrapper) processConfigureMake(runner utils.Runner, rule Rule, iFlagsSlice *[]string, iFlagDedup map[string]bool, gopathRoot string) error {
	br.Logger.Debugw("process cquery response using CONFIGURE", "clibName", rule.Name)
	var includePrefix string
	for _, attr := range rule.Attributes {
		if isIncPrefix(attr) {
			includePrefix = attr.StringValue
		}
	}
	err := br.extractBazelGenIncPath(runner, rule, iFlagsSlice, iFlagDedup, gopathRoot, includePrefix)
	if err != nil {
		return fmt.Errorf("failed to extract bazel gen inc path: %w", err)
	}
	return nil
}

func (br *gopathWrapper) processCqueryResponse(runner utils.Runner, resp CqueryResponse, iFlagsSlice *[]string, iFlagDedup map[string]bool, gopathRoot string) error {
	// Iterate over each of the results and process the cquery response.
	for _, r := range resp.Results {
		rule := r.Target.Rule
		br.Logger.Debugw("process cquery response", "clibName", rule.Name)
		colonIndex := strings.IndexRune(rule.Location, ':')
		if colonIndex == -1 {
			continue
		}
		locationNoLine := rule.Location[:colonIndex]
		libLocationPath := filepath.Dir(locationNoLine)

		switch rule.RuleClass {
		case "cc_library":
			if strings.Contains(rule.Name, "@bazel_tools//") {
				continue
			}
			err := br.processCCLibrary(runner, rule, libLocationPath, iFlagsSlice, iFlagDedup, gopathRoot)
			if err != nil {
				br.Logger.Errorf("failed to process cc_library: %w", err)
				return err
			}
		case "cmake":
			err := br.processCMake(runner, rule, iFlagsSlice, iFlagDedup, gopathRoot)
			if err != nil {
				br.Logger.Errorf("failed to process cmake: %w", err)
				return err
			}
		case "configure_make":
			err := br.processConfigureMake(runner, rule, iFlagsSlice, iFlagDedup, gopathRoot)
			if err != nil {
				br.Logger.Errorf("failed to process configure: %w", err)
				return err
			}
		default:
			br.Logger.Infow("process cquery response (skip)", "clibName", rule.Name)
		}
	} // end of for loop
	return nil
}

func (br *gopathWrapper) configQuery(runner utils.Runner, ccLib string) (CqueryResponse, error) {
	var resp CqueryResponse
	// Retrieve detailed build information about the cc_library target in JSON format.
	br.Logger.Debugw("run configQuery", "ccLib", ccLib)
	ccLibInfo, _, err := utils.ExecCommand(runner, br.BazelPath, "cquery", "--bes_backend=", "--output=jsonproto", fmt.Sprintf("%s", ccLib))
	if err != nil {
		return resp, fmt.Errorf("failed to get cquery output for %s: %w", ccLib, err)
	}
	if err := json.Unmarshal([]byte(ccLibInfo), &resp); err != nil {
		return resp, fmt.Errorf("failed to parse cquery output for %s: %w", ccLib, err)
	}
	return resp, nil
}

// isCopts returns true if the attribute is of type `copts`
func isCopts(attr Attribute) bool {
	return attr.Name == "copts" && attr.ExplicitlySpecified
}

// isIncPrefix returns true if the attribute is of type `include_prefix`
func isIncPrefix(attr Attribute) bool {
	return attr.Name == "include_prefix" && attr.ExplicitlySpecified
}

// isCopts returns true if the attribute is of type `copts`
func isCdeps(attr Attribute) bool {
	return attr.Name == "cdeps" && attr.ExplicitlySpecified
}

func srcGo(attr Attribute) bool {
	return attr.Name == "srcs" && attr.ExplicitlySpecified
}

// isRawSrcsOrHdrs returns true if the attribute is of type `srcs` or `hdrs` and has a non-empty value.
func isRawSrcsOrHdrs(attr Attribute) bool {
	return (attr.Name == "srcs" && attr.ExplicitlySpecified && len(attr.StringListValue) > 0) ||
		(attr.Name == "hdrs" && attr.ExplicitlySpecified && len(attr.StringListValue) > 0)
}

// getNormalizedIFlag normalizes the `-I` flag by replacing the prefix "-I.//" with the dependency root.
// It returns the normalized flag and a boolean indicating whether the flag was normalized.
// For example, convert `-I.//source/common` to `-I/path/to/dependency/root/source/common`.
func getNormalizedIFlag(depRoot, flag string) (string, bool) {
	if strings.HasPrefix(flag, "-I.//") {
		suffix := strings.TrimPrefix(flag, "-I.//")
		return fmt.Sprintf("-I%s/%s", depRoot, suffix), true
	}
	return flag, false
}

// isStdCopt reports whether the copt selects the C/C++ language standard
// (e.g. "-std=c++17" or "-std=c11"). These are forwarded verbatim to cgo
// because, unlike include paths, there is no other mechanism that reproduces
// them for the non-Bazel cgo build.
func isStdCopt(flag string) bool {
	return strings.HasPrefix(flag, "-std=")
}

// copySrcHdrFiles copies the cc_library rule's declared source/header files to the lifted path location, preserving any relative subdirectory structure. It returns the path of the copied files and an error, if any.
//
// Only the files the rule explicitly declares in srcs/hdrs are copied. Copying
// the whole directory (cp -r) would also drag in sibling files the rule does
// not declare — e.g. a testonly cgo package in a `test/` subdirectory — whose
// .go files then leak into the lift and abort package loading. srcs/hdrs are
// C/C++ only, so real Go dependencies (materialized separately by go_path) are
// never touched.
func (br *gopathWrapper) copySrcHdrFiles(runner utils.Runner, libLocationPath, gopathRoot, includePrefix string, files []string) (string, error) {
	// handle internal dependency
	// Consider the example below to understand the input and output paths:
	// libLocationPath: /path/to/workspace/src/example.com/crypto/core
	// gopathRoot: /path/to/bazel/cache/execroot/__main__/bazel-out/k8-fastbuild/bin/src/example.com/svc/svc-anal

	// Prepare destination path for copying by trimming the workspace prefix.
	// Example destPath: /path/to/bazel/cache/execroot/__main__/bazel-out/k8-fastbuild/bin/src/example.com/svc/svc-anal/src/example.com/crypto
	destPath := filepath.Join(gopathRoot, strings.TrimPrefix(filepath.Dir(libLocationPath), br.Workspace))
	// If the library is not found in the monorepo, skip it.
	if len(destPath) == 0 {
		br.Logger.Debugf("raw cc_library rule not found in monorepo: %s", libLocationPath)
		return "", fmt.Errorf("raw cc_library rule not found in monorepo: %s", libLocationPath)
	}
	// By default, the folder is read-only, relax it in order to write into it.
	if _, _, err := utils.ExecCommand(runner, "chmod", "-R", "777", gopathRoot); err != nil {
		return "", fmt.Errorf("failed to make %q writable: %w", gopathRoot, err)
	}

	// Example finalDestPath: /path/to/bazel/cache/execroot/__main__/bazel-out/k8-fastbuild/bin/src/example.com/svc/svc-anal/src/example.com/crypto/core
	finalDestPath := filepath.Join(destPath, filepath.Base(libLocationPath))

	// Copy each declared source/header file, recreating its parent directory as
	// needed. srcs/hdrs come back from cquery as labels (e.g. "//pkg/path:foo.h"
	// or "pkg/path:sub/foo.h"); the file name relative to the rule's own package
	// is the part after the last ":". os.MkdirAll is idempotent, so it also
	// creates finalDestPath itself when copying the first top-level file.
	for _, f := range files {
		name := f
		if idx := strings.LastIndex(f, ":"); idx >= 0 {
			name = f[idx+1:]
		}
		srcFile := filepath.Join(libLocationPath, name)
		dstFile := filepath.Join(finalDestPath, name)
		if err := os.MkdirAll(filepath.Dir(dstFile), 0o755); err != nil {
			return "", fmt.Errorf("failed to create raw cc_library directory %q: %w", filepath.Dir(dstFile), err)
		}
		if err := copyFile(srcFile, dstFile); err != nil {
			return "", fmt.Errorf("failed to copy raw cc_library file from %q to %q: %w", srcFile, dstFile, err)
		}
	}
	return finalDestPath, nil
}

func folderExists(basePath string, folderNames []string) (string, error) {
	for _, name := range folderNames {
		fullPath := filepath.Join(basePath, name)
		info, err := os.Stat(fullPath)
		if err == nil && info.IsDir() {
			return name, nil
		} else if err != nil && !os.IsNotExist(err) {
			return "", err // some other error
		}
	}
	return "", nil // none found
}

func removeCgoPkgConfigLinesFromFile(filePath string) error {
	// Remove "#cgo pkg-config: xxx" lines from the file
	// CGO macro causes build error and must be removed.
	inputFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	var cleanedLines []string
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "cgo pkg-config:") {
			cleanedLines = append(cleanedLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Write the modified content back to the file
	return os.WriteFile(filePath, []byte(strings.Join(cleanedLines, "\n")), 0644)
}

var importPathRegex = regexp.MustCompile(`importpath\s*=\s*"([^"]+)"`)

// getImportPathFromBazelFile parses the bazel file and returns the import path.
// Using importpath to find copied external src files.
func getImportPathFromBazelFile(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	matches := importPathRegex.FindStringSubmatch(string(content))
	if len(matches) < 2 {
		return "", fmt.Errorf("importpath not found in file")
	}

	return matches[1], nil
}

// copyFile copies a regular file from src to dst, creating or truncating dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
