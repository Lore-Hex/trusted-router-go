package trustedrouter_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const modulePath = "github.com/Lore-Hex/trusted-router-go"

func dxCommand(t *testing.T, dir string, argv ...string) []byte {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(argv, " "), err, out)
	}
	return out
}

func dxRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func dxWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestReleaseArtifact builds a canonical module ZIP, asserts its independent
// inventory, then extracts it for consumers. TR_DX_OUTPUT retains this artifact.
func TestReleaseArtifact(t *testing.T) {
	var mod struct{ Path, Dir, GoVersion string }
	if err := json.Unmarshal(dxCommand(t, ".", "go", "list", "-m", "-json"), &mod); err != nil {
		t.Fatal(err)
	}
	if mod.Path != modulePath || mod.GoVersion != "1.23" {
		t.Fatalf("module metadata: %+v", mod)
	}
	readme := string(dxRead(t, "README.md"))
	for _, value := range []string{"Apache-2.0", "https://github.com/Lore-Hex/trusted-router-go", "https://trustedrouter.com", "https://pkg.go.dev/" + modulePath, "Topics:", "Go 1.23", "Go SDK for TrustedRouter"} {
		if !strings.Contains(readme, value) {
			t.Errorf("missing metadata %q", value)
		}
	}
	expected := strings.Fields(string(dxRead(t, "testdata/release-files.txt")))
	// Select the release source set independently of the expected inventory.
	var files []string
	entries, err := os.ReadDir(mod.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			files = append(files, name)
		}
	}
	files = append(files, "LICENSE", "README.md", "go.mod")
	err = filepath.WalkDir("cmd", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !strings.HasSuffix(path, "_test.go") {
			files = append(files, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	prefix := modulePath + "@v0.4.0/"
	for _, name := range files {
		w, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(dxRead(t, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var actual []string
	for _, f := range zr.File {
		actual = append(actual, strings.TrimPrefix(f.Name, prefix))
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("artifact listing mismatch\ngot %v\nwant %v", actual, expected)
	}
	out := os.Getenv("TR_DX_OUTPUT")
	if out == "" {
		out = t.TempDir()
	}
	dxWrite(t, filepath.Join(out, "module.zip"), archive.Bytes())
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		dxWrite(t, filepath.Join(out, "module", strings.TrimPrefix(f.Name, prefix)), b)
	}
	dxWrite(t, filepath.Join(out, "listing.txt"), []byte(strings.Join(actual, "\n")+"\n"))
	t.Logf("artifact: %s (%d files)", out, len(actual))
}

// TestModuleInventory notices unexpected fixture, script, CI and scratch growth,
// including files that a staged release excludes but a source-tag proxy ships.
func TestModuleInventory(t *testing.T) {
	var got []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".reference" || strings.HasPrefix(d.Name(), ".codex")) {
			return filepath.SkipDir
		}
		if !d.IsDir() && path != ".git" {
			got = append(got, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := strings.Fields(string(dxRead(t, "testdata/module-files.txt")))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("module source inventory mismatch\ngot %v\nwant %v", got, want)
	}
}

func TestExportedDocumentation(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pkg := pkgs["trustedrouter"]
	docs := doc.New(pkg, modulePath, doc.PreserveAST)
	if docs.Doc == "" {
		t.Error("missing package documentation")
	}
	check := func(name, comment string) {
		if strings.TrimSpace(comment) == "" {
			t.Errorf("missing doc comment: %s", name)
		}
	}
	for _, f := range docs.Funcs {
		check(f.Name, f.Doc)
	}
	for _, typ := range docs.Types {
		check(typ.Name, typ.Doc)
		for _, f := range typ.Methods {
			check(typ.Name+"."+f.Name, f.Doc)
		}
		for _, f := range typ.Funcs {
			check(f.Name, f.Doc)
		}
	}
	// go/doc groups const/var declarations; inspect each exported spec and field too.
	for _, file := range pkg.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.GenDecl:
				for _, sp := range v.Specs {
					if value, ok := sp.(*ast.ValueSpec); ok {
						for _, name := range value.Names {
							if name.IsExported() {
								comment := value.Doc.Text()
								if comment == "" {
									comment = v.Doc.Text()
								}
								check(name.Name, comment)
							}
						}
					}
				}
			case *ast.TypeSpec:
				if !v.Name.IsExported() {
					return false
				}
			case *ast.Field:
				for _, name := range v.Names {
					if name.IsExported() {
						check(name.Name, v.Doc.Text()+v.Comment.Text())
					}
				}
			}
			return true
		})
	}
}

func artifactForConsumer(t *testing.T) string {
	t.Helper()
	out := t.TempDir()
	cmd := exec.Command("go", "test", "-count=1", "-run", "^TestReleaseArtifact$", ".")
	cmd.Env = append(os.Environ(), "TR_DX_OUTPUT="+out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build artifact: %v\n%s", err, b)
	}
	return filepath.Join(out, "module")
}

func consumerModule(t *testing.T, artifact string) string {
	t.Helper()
	dir := t.TempDir()
	dxWrite(t, filepath.Join(dir, "go.mod"), []byte("module consumer.example/smoke\n\ngo 1.23\n\nrequire "+modulePath+" v0.4.0\nreplace "+modulePath+" => "+artifact+"\n"))
	return dir
}

func TestScratchConsumer(t *testing.T) {
	artifact := downloadArtifact(t, artifactForConsumer(t))
	dir := consumerModule(t, artifact)
	// This is exactly the same public example that go test executes locally.
	dxWrite(t, filepath.Join(dir, "example_test.go"), dxRead(t, "example_test.go"))
	out := dxCommand(t, dir, "go", "test", "-v", ".")
	if !bytes.Contains(out, []byte("PASS: ExampleClient_ChatCompletions")) {
		t.Fatalf("example did not run: %s", out)
	}
	out = dxCommand(t, dir, "go", "doc", modulePath+".Client.ChatCompletions")
	if !bytes.Contains(out, []byte("ChatCompletions collects")) {
		t.Fatalf("consumer docs absent: %s", out)
	}
	dxCommand(t, artifact, "go", "build", "-o", filepath.Join(dir, "trustedrouter"), "./cmd/trustedrouter")
}

// downloadArtifact asks the Go module downloader to validate the release ZIP
// through a local file proxy before the scratch consumer uses its module root.
func downloadArtifact(t *testing.T, artifact string) string {
	t.Helper()
	proxy := t.TempDir()
	versionDir := filepath.Join(proxy, "github.com/!lore-!hex/trusted-router-go/@v")
	dxWrite(t, filepath.Join(versionDir, "v0.4.0.zip"), dxRead(t, filepath.Join(filepath.Dir(artifact), "module.zip")))
	dxWrite(t, filepath.Join(versionDir, "v0.4.0.mod"), dxRead(t, filepath.Join(artifact, "go.mod")))
	dxWrite(t, filepath.Join(versionDir, "v0.4.0.info"), []byte(`{"Version":"v0.4.0","Time":"2026-01-01T00:00:00Z"}`))
	cmd := exec.Command("go", "mod", "download", "-json", modulePath+"@v0.4.0")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=file://"+filepath.ToSlash(proxy), "GOSUMDB=off", "GOMODCACHE="+t.TempDir(), "GOFLAGS=-modcacherw")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("module ZIP download: %v\n%s", err, out)
	}
	var downloaded struct{ Dir string }
	if err := json.Unmarshal(out, &downloaded); err != nil {
		t.Fatal(err)
	}
	if downloaded.Dir == "" {
		t.Fatalf("missing downloaded module: %s", out)
	}
	return downloaded.Dir
}
