// boundary-check supplements golangci-lint with two wire-specific invariants.
package main

import (
	"bytes"
	"context"
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
)

type packageInfo struct {
	ImportPath, Dir, Export string
	GoFiles                 []string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	command := exec.CommandContext(context.Background(), "go", "list", "-deps", "-export", "-json", "./...")
	raw, err := command.Output()
	if err != nil {
		return fmt.Errorf("load packages: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	packages := map[string]packageInfo{}
	var local []packageInfo
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	for {
		var pkg packageInfo
		if err := decoder.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		packages[pkg.ImportPath] = pkg
		rel, err := filepath.Rel(root, pkg.Dir)
		if err == nil && rel != ".." && !filepath.IsAbs(rel) && !bytes.HasPrefix([]byte(rel), []byte(".."+string(filepath.Separator))) {
			local = append(local, pkg)
		}
	}
	fset := token.NewFileSet()
	imports := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		pkg, ok := packages[path]
		if !ok || pkg.Export == "" {
			return nil, fmt.Errorf("missing export for %s", path)
		}
		return os.Open(pkg.Export)
	})
	findings := 0
	for _, pkg := range local {
		var files []*ast.File
		for _, name := range pkg.GoFiles {
			file, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), nil, 0)
			if err != nil {
				return err
			}
			files = append(files, file)
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
		config := types.Config{Importer: imports}
		if _, err := config.Check(pkg.ImportPath, fset, files, info); err != nil {
			return err
		}
		report := func(pos token.Pos, rule string) { fmt.Printf("%s: %s\n", fset.Position(pos), rule); findings++ }
		for _, file := range files {
			ast.Inspect(file, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.IndexExpr:
					if named, ok := info.TypeOf(node.X).(*types.Named); ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "Header" {
						report(node.Pos(), "header-access: use Header.Get/Set/Add/Values/Del")
					}
				case *ast.SelectorExpr:
					if fn, ok := info.Uses[node.Sel].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "encoding/json" && fn.Name() == "DisallowUnknownFields" {
						report(node.Pos(), "wire-pass-through: DisallowUnknownFields rejects future producer metadata")
					}
				}
				return true
			})
		}
	}
	if findings != 0 {
		return fmt.Errorf("%d boundary findings", findings)
	}
	fmt.Println("boundary-check: 0 findings")
	return nil
}
