package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMutationOutcomesAndRestoration(t *testing.T) {
	for _, tc := range []struct{ name, before, after, want string }{
		{"killed", "Value = 1", "Value = 2", ""},
		{"survives", "Value = 1", "Value = 1 // unchanged behavior", "SURVIVED"},
		{"stale", "Value = 99", "Value = 2", "STALE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			original := []byte("package fixture\nconst Value = 1\n")
			for name, data := range map[string][]byte{
				"go.mod":          []byte("module fixture\n\ngo 1.23\n"),
				"fixture.go":      original,
				"fixture_test.go": []byte("package fixture\nimport \"testing\"\nfunc TestValue(t *testing.T) { if Value != 1 { t.Fatal(Value) } }\n"),
			} {
				if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := checkMutation(context.Background(), root, mutation{Name: tc.name, File: "fixture.go", Before: tc.before, After: tc.after, Test: "TestValue"})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wanted %s, got %v", tc.want, err)
			}
			restored, err := os.ReadFile(filepath.Join(root, "fixture.go"))
			if err != nil || !bytes.Equal(restored, original) {
				t.Fatalf("original bytes not restored: %s, %v", restored, err)
			}
		})
	}
}
