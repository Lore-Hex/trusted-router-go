package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Each probe must compile, fail its static gate, and name the intended rule.
// These are separate runs so one finding cannot mask another class.
func checkStaticProbes(ctx context.Context, root string) error {
	probes := []struct {
		name, source, rule string
		args               []string
	}{
		{"unchecked assertion", `package trustedrouter
func BoundaryProbe(v any) string { return v.(string) }
`, "(forcetypeassert)", nil},
		{"pass-through rejection", `package trustedrouter
import "encoding/json"
func BoundaryProbe(d *json.Decoder) { d.DisallowUnknownFields() }
`, "wire-pass-through:", []string{"run", "./scripts/boundary-check"}},
		{"raw header indexing", `package trustedrouter
import "net/http"
func BoundaryProbe(h http.Header) []string { return h["x-probe"] }
`, "header-access:", []string{"run", "./scripts/boundary-check"}},
		{"ignored JSON error", `package trustedrouter
import "encoding/json"
func BoundaryProbe(b []byte) any { var v any; _ = json.Unmarshal(b, &v); return v }
`, "(errcheck)", nil},
	}
	for _, probe := range probes {
		args := probe.args
		if args == nil {
			args = []string{"run", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.0", "run", "./..."}
		}
		started := time.Now()
		if err := checkStaticProbe(ctx, root, probe.source, probe.rule, args); err != nil {
			return fmt.Errorf("static probe %s: %w", probe.name, err)
		}
		fmt.Printf("REJECTED static %-25s %s (%s)\n", probe.name, probe.rule, time.Since(started).Round(time.Millisecond))
	}
	return nil
}

func checkStaticProbe(ctx context.Context, root, source, rule string, args []string) (result error) {
	path := filepath.Join(root, "boundary_probe.go")
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("probe path already exists or is inaccessible")
	}
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.Remove(path)) }()
	// Build first: a compiler failure must not count as a static rejection.
	if out, err := command(ctx, root, "go", "build", "./..."); err != nil {
		return fmt.Errorf("probe failed to compile: %w\n%s", err, out)
	}
	out, err := command(ctx, root, "go", args...)
	if err == nil || !bytes.Contains(out, []byte("boundary_probe.go:")) || !bytes.Contains(out, []byte(rule)) {
		return errors.Join(fmt.Errorf("missing intended finding %s:\n%s", rule, out), err)
	}
	return nil
}
