// mutation-check proves focused tests fail when recorded boundary repairs regress.
// All edits are made in a temporary worktree copy, never using git checkout.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

//go:embed mutations.json
var manifest []byte

type mutation struct{ Name, File, Before, After, Test string }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) (result error) {
	started := time.Now()
	defer func() { fmt.Printf("mutation-check wall time: %s\n", time.Since(started).Round(time.Millisecond)) }()
	var mutations []mutation
	if err := json.Unmarshal(manifest, &mutations); err != nil {
		return err
	}
	if len(mutations) == 0 {
		return errors.New("empty mutation manifest")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	module, err := os.ReadFile(filepath.Join(root, "go.mod")) //nolint:gosec // G304: fixed file in the explicitly selected local repository.
	if err != nil || !bytes.Contains(module, []byte("module github.com/Lore-Hex/trusted-router-go\n")) {
		return errors.New("run mutation-check from repository root")
	}
	scratch, err := os.MkdirTemp("", "trusted-router-mutations-")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(scratch)) }()
	if err := copyTree(root, scratch); err != nil {
		return err
	}
	// Preflight every pattern before running anything: stale or duplicate records fail closed.
	tests := map[string]bool{}
	var names []string
	for _, m := range mutations {
		if !fs.ValidPath(m.File) {
			return fmt.Errorf("invalid manifest path %q", m.File)
		}
		original, err := os.ReadFile(filepath.Join(scratch, m.File)) //nolint:gosec // G304: validated relative path from the embedded manifest, inside the temporary copy.
		if err != nil {
			return err
		}
		if m.Before == "" || m.Before == m.After || strings.Count(string(original), m.Before) != 1 {
			return fmt.Errorf("STALE %s: before must match exactly once", m.Name)
		}
		if !tests[m.Test] {
			tests[m.Test] = true
			names = append(names, m.Test)
		}
	}
	if out, err := command(ctx, scratch, "go", "test", "-count=1", "-run", "^("+strings.Join(names, "|")+")$", "."); err != nil {
		return fmt.Errorf("baseline tests failed: %w\n%s", err, out)
	}
	fmt.Printf("baseline: %d focused tests passed\n", len(names))
	for _, m := range mutations {
		if err := checkMutation(ctx, scratch, m); err != nil {
			return err
		}
	}
	// The supplemental static gate is part of this command as well as a CI step.
	if out, err := command(ctx, scratch, "go", "run", "./scripts/boundary-check"); err != nil {
		return fmt.Errorf("boundary gate: %w\n%s", err, out)
	}
	if err := checkStaticProbes(ctx, scratch); err != nil {
		return err
	}
	fmt.Printf("KILLED %d/%d mutations; boundary gate passed\n", len(mutations), len(mutations))
	return nil
}

func checkMutation(ctx context.Context, root string, m mutation) (result error) {
	path := filepath.Join(root, m.File)
	original, err := os.ReadFile(path) //nolint:gosec // G304: embedded manifest selects a source file in the temporary copy.
	if err != nil {
		return err
	}
	// Restore the original bytes from memory even on a surviving mutant, test
	// infrastructure failure, canceled subprocess, or panic. Never invoke git.
	defer func() {
		if err := os.WriteFile(path, original, 0600); err != nil {
			result = errors.Join(result, fmt.Errorf("restore %s: %w", m.File, err))
			return
		}
		restored, err := os.ReadFile(path) //nolint:gosec // G304: verify the exact file just restored in the temporary copy.
		if err != nil {
			result = errors.Join(result, err)
		} else if !bytes.Equal(original, restored) {
			result = errors.Join(result, errors.New("restoration mismatch"))
		}
	}()
	if strings.Count(string(original), m.Before) != 1 {
		return fmt.Errorf("STALE %s", m.Name)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(original), m.Before, m.After, 1)), 0600); err != nil {
		return err
	}
	started := time.Now()
	out, err := command(ctx, root, "go", "test", "-count=1", "-run", "^"+m.Test+"$", ".")
	if err == nil {
		return fmt.Errorf("SURVIVED %s (%s)", m.Name, m.Test)
	}
	// Build errors and environmental failures are not evidence that a test killed a mutant.
	if !bytes.Contains(out, []byte("--- FAIL: "+m.Test)) || bytes.Contains(out, []byte("[build failed]")) || ctx.Err() != nil {
		return fmt.Errorf("invalid proof %s: %w\n%s", m.Name, err, out)
	}
	fmt.Printf("KILLED %-36s %s (%s)\n", m.Name, m.Test, time.Since(started).Round(time.Millisecond))
	return nil
}

func command(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if len(args) > 1 && strings.Contains(args[1], "golangci-lint@v2.6.0") {
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	}
	return cmd.CombinedOutput()
}

func copyTree(source, target string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if entry.Name() == ".git" || entry.Name() == ".agents" || entry.Name() == ".codex" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		destination := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported file type: %s", rel)
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: WalkDir selected a regular file under the repository; symlinks are rejected.
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, 0600)
	})
}
