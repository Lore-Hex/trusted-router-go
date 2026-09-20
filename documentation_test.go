package trustedrouter_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocumentationExamples compiles the literal Go fences in README and docs
// against the extracted release. Fragments share the documented client context;
// only their surrounding scope and unused-result sinks are supplied here.
func TestDocumentationExamples(t *testing.T) {
	artifact := artifactForConsumer(t)
	paths := []string{"README.md"}
	err := filepath.WalkDir("docs", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".md") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, path := range paths {
		lines := strings.Split(string(dxRead(t, path)), "\n")
		for i := 0; i < len(lines); i++ {
			if !strings.HasPrefix(lines[i], "```") {
				continue
			}
			lang := strings.TrimSpace(strings.TrimPrefix(lines[i], "```"))
			start := i + 1
			i++
			var block []string
			for ; i < len(lines) && lines[i] != "```"; i++ {
				block = append(block, lines[i])
			}
			if i == len(lines) {
				t.Fatalf("unclosed fence %s:%d", path, start)
			}
			if lang == "text" || lang == "" {
				continue
			}
			if lang != "go" && lang != "sh" {
				t.Fatalf("untested language %s in %s:%d", lang, path, start)
			}
			code := strings.Join(block, "\n") + "\n"
			t.Run(fmt.Sprintf("%s:%d", path, start), func(t *testing.T) {
				dir := consumerModule(t, artifact)
				if lang == "sh" {
					dxWrite(t, filepath.Join(dir, "example.sh"), []byte(code))
					dxCommand(t, dir, "sh", "-n", "example.sh")
					return
				}
				if !strings.HasPrefix(code, "package ") {
					code = fragmentProgram(t, code)
				}
				dxWrite(t, filepath.Join(dir, "main.go"), []byte(code))
				dxCommand(t, dir, "go", "build", ".")
			})
			if lang == "go" {
				count++
			}
		}
	}
	if count == 0 {
		t.Fatal("no Go documentation examples found")
	}
}

func fragmentProgram(t *testing.T, code string) string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "snippet.go", "package main\nfunc main(){\n"+code+"\n}", 0)
	if err != nil {
		t.Fatal(err)
	}
	imports := map[string]string{"trustedrouter": modulePath, "context": "context"}
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := s.X.(*ast.Ident); ok && (id.Name == "fmt" || id.Name == "errors") {
				imports[id.Name] = id.Name
			}
		}
		return true
	})
	prelude := "package main\nimport (\n"
	for alias, path := range imports {
		prelude += fmt.Sprintf("%s %q\n", alias, path)
	}
	prelude += `) 
var client *trustedrouter.Client
var ctx = context.Background()
var err error
var tlsCertDER, serializedRequest, responseBytes []byte
var receiptJWS, requestNonce string
func main() {
`
	var sink string
	for _, statement := range f.Decls[0].(*ast.FuncDecl).Body.List {
		switch s := statement.(type) {
		case *ast.AssignStmt:
			if s.Tok == token.DEFINE {
				for _, lhs := range s.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
						sink += "\n_ = " + id.Name
					}
				}
			}
		case *ast.DeclStmt:
			for _, spec := range s.Decl.(*ast.GenDecl).Specs {
				if v, ok := spec.(*ast.ValueSpec); ok {
					for _, id := range v.Names {
						sink += "\n_ = " + id.Name
					}
				}
			}
		}
	}
	return prelude + code + sink + "\n}\n"
}
