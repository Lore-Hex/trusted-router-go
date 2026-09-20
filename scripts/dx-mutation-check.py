#!/usr/bin/env python3
"""Prove consumer guards and every CLI case fail; mutate temporary copies only."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


def run(root, args, env=None):
    result = subprocess.run(args, cwd=root, env={**os.environ, **(env or {})},
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=180)
    return result.returncode, result.stdout


def passed(root, args, env=None):
    code, output = run(root, args, env)
    if code:
        raise RuntimeError(f"baseline failed: {args}\n{output}")
    return output


def killed(root, name, test, path, before, after, diagnostic):
    original = path.read_bytes() if path.exists() else None
    if before is not None and (original is None or original.count(before) != 1):
        raise RuntimeError(f"STALE {name}")
    if before is None and original is not None:
        raise RuntimeError(f"probe already exists: {path}")
    try:
        path.write_bytes(after if before is None else original.replace(before, after))
        code, output = run(root, ["go", "test", "-count=1", "-run", f"^{test}$", "."])
        if code == 0 or f"--- FAIL: {test}" not in output or diagnostic not in output:
            raise RuntimeError(f"SURVIVED or invalid proof {name}\n{output}")
        print(f"KILLED {name}: {test}", flush=True)
    finally:
        if original is None:
            path.unlink()
        else:
            path.write_bytes(original)
            if path.read_bytes() != original:
                raise RuntimeError(f"restoration mismatch: {path}")


def main():
    started = time.monotonic()
    source = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="trusted-router-dx-mutations-") as temp:
        temp = Path(temp)
        root = temp / "repo"
        shutil.copytree(source, root, ignore=shutil.ignore_patterns(".git", ".reference", ".codex-*", "__pycache__"))
        focused = "TestReleaseArtifact|TestModuleInventory|TestExportedDocumentation|TestDocumentationExamples|TestScratchConsumer"
        passed(root, ["go", "test", "-count=1", "-run", f"^({focused})$", "."])
        probes = [
            ("artifact-stray-file", "TestReleaseArtifact", "cmd/trustedrouter/stray.txt", None, b"scratch\n", "artifact listing mismatch"),
            ("module-fixture-bloat", "TestModuleInventory", "testdata/stray.json", None, b"{}\n", "module source inventory mismatch"),
            ("readme-broken-example", "TestDocumentationExamples", "README.md", b"trustedrouter.NewClient(", b"trustedrouter.NonexistentClient(", "undefined: trustedrouter.NonexistentClient"),
            ("metadata-doc-url", "TestReleaseArtifact", "README.md", b"https://pkg.go.dev/github.com/Lore-Hex/trusted-router-go", b"https://example.invalid/docs", "missing metadata"),
            ("doc-function", "TestExportedDocumentation", "client.go", b"// NewClient constructs a TrustedRouter client.", b"", "missing doc comment: NewClient"),
            ("doc-type", "TestExportedDocumentation", "provider.go", b"// ProviderPreferences configures typed provider routing, privacy, and pricing.", b"", "missing doc comment: ProviderPreferences"),
            ("doc-package", "TestExportedDocumentation", "doc.go", (root / "doc.go").read_bytes().split(b"package trustedrouter")[0], b"", "missing package documentation"),
            ("doc-method", "TestExportedDocumentation", "boundary.go", b"// Unwrap returns the underlying error for errors.Is and errors.As.", b"", "missing doc comment: ResponseShapeError.Unwrap"),
            ("doc-field", "TestExportedDocumentation", "receipts.go", b"// RequestBody supplies the exact serialized request bytes; nil means absent.", b"", "missing doc comment: RequestBody"),
            ("doc-constant", "TestExportedDocumentation", "constants.go", b"// DefaultAPIBaseURL is the default OpenAI-compatible TrustedRouter inference base URL.", b"", "missing doc comment: DefaultAPIBaseURL"),
            ("consumer-example-output", "TestScratchConsumer", "example_test.go", b"// Output: Hello from TrustedRouter!", b"// Output: incorrect result", "want:"),
            ("consumer-invalid-zip", "TestScratchConsumer", "consumer_dx_test.go", b'dxRead(t, filepath.Join(filepath.Dir(artifact), "module.zip"))', b'[]byte("broken zip")', "module ZIP download"),
            ("consumer-visible-doc", "TestScratchConsumer", "chat.go", b"// ChatCompletions collects a streamed TrustedRouter chat response into a chat completion.", b"", "consumer docs absent"),
        ]
        for name, test, file, before, after, diagnostic in probes:
            killed(root, name, test, root / file, before, after, diagnostic)
        cli_binary = temp / "artifact-cli"
        baseline = passed(root, ["go", "test", "-json", "-count=1", "-run", "^TestCLI$", "./cmd/trustedrouter"],
                          {"TR_DX_CLI_SAVE": str(cli_binary)})
        cases = [event["Test"].split("/", 1)[1] for line in baseline.splitlines()
                 if (event := json.loads(line)).get("Action") == "pass" and event.get("Test", "").startswith("TestCLI/")]
        if not cases:
            raise RuntimeError("no CLI cases discovered")
        runner = temp / "cli-contract-tests"
        passed(root, ["go", "test", "-c", "-o", str(runner), "./cmd/trustedrouter"])
        for case in cases:
            for mode in ("exit", "shape"):
                code, output = run(root / "cmd/trustedrouter",
                                   [str(runner), "-test.v", "-test.run", "^TestCLI$/^" + re.escape(case) + "$"],
                                   {"TR_DX_CLI_BINARY": str(cli_binary), "TR_DX_CLI_MUTATE": case + ":" + mode})
                if code == 0 or "--- FAIL: TestCLI/" + case not in output:
                    raise RuntimeError(f"SURVIVED or invalid proof CLI {case}:{mode}\n{output}")
                diagnostic = "exit =" if mode == "exit" else ("JSON shape", "stdout =", "stderr =")
                if not any(text in output for text in ([diagnostic] if isinstance(diagnostic, str) else diagnostic)):
                    raise RuntimeError(f"wrong failure for CLI {case}:{mode}\n{output}")
                print(f"KILLED CLI {case}:{mode}", flush=True)
        print(f"KILLED {len(probes) + 2 * len(cases)} consumer/CLI mutations; "
              f"{len(cases)} CLI cases; restored all source bytes; {time.monotonic() - started:.2f}s", flush=True)


if __name__ == "__main__":
    main()
