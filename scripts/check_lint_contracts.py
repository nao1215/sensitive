#!/usr/bin/env python3
"""Check real lint tools against forbidden dependency and constructor mutations."""
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def reject(cwd, command, needle):
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if result.returncode == 0 or needle not in result.stdout:
        raise RuntimeError(f"negative fixture did not fail as expected: {command}\n{result.stdout}")


with tempfile.TemporaryDirectory(prefix="embargo-lint-") as directory:
    repo = pathlib.Path(directory) / "repo"
    shutil.copytree(ROOT, repo, ignore=shutil.ignore_patterns(".git", "cover.*", "coverage*", ".gremlins", "tests"))
    # go-arch-lint parses imports without asking the compiler to resolve cycles.
    edges = [
        (".", "embargo", "github.com/nao1215/embargo/embargotest"),
        ("internal/detect", "detect", "github.com/nao1215/embargo"),
        ("internal/ascii", "ascii", "github.com/nao1215/embargo/internal/detect"),
        ("embargotest", "embargotest", "github.com/nao1215/embargo/internal/detect"),
    ]
    for folder, package, dependency in edges:
        fixture = repo / folder / "lint_contract_fixture.go"
        fixture.write_text(f'package {package}\nimport _ "{dependency}"\n')
        try:
            reject(repo, ["go", "run", "github.com/fe3dback/go-arch-lint@v1.19.0", "check"], "dependency")
        finally:
            fixture.unlink()
    fixture = repo / "lint_contract_fixture.go"
    fixture.write_text('package embargo\nimport alias "testing"\nfunc lintContract() bool { return alias.Short() }\n')
    try:
        reject(repo, ["golangci-lint", "run", "--enable-only", "depguard"], "depguard")
    finally:
        fixture.unlink()
    fixture = repo / "embargotest" / "lint_contract_fixture.go"
    fixture.write_text('package embargotest\nimport alias "github.com/nao1215/embargo/internal/detect"\nfunc lintContract() string { return string(alias.NamePAN) }\n')
    try:
        reject(repo, ["golangci-lint", "run", "--enable-only", "depguard"], "depguard")
    finally:
        fixture.unlink()
    recorder = repo / "embargotest" / "recorder.go"
    original = recorder.read_text()
    recorder.write_text(original.replace("type Recorder struct {", "type Recorder struct {\n addedContractField bool", 1))
    try:
        reject(repo, ["golangci-lint", "run", "--enable-only", "exhaustruct_v5"], "addedContractField")
    finally:
        recorder.write_text(original)
    handler = repo / "slog_handler.go"
    original_handler = handler.read_text()
    handler.write_text(original_handler.replace("type slogHandler struct {", "type slogHandler struct {\n addedContractField bool", 1))
    try:
        reject(repo, ["golangci-lint", "run", "--enable-only", "exhaustruct_v5"], "addedContractField")
    finally:
        handler.write_text(original_handler)
    # A mixed receiver outside Input's two explicit decoder exceptions must fail.
    fixture = repo / "lint_contract_fixture.go"
    fixture.write_text('package embargo\ntype receiverContract struct{}\nfunc (receiverContract) Read() {}\nfunc (*receiverContract) Write() {}\n')
    try:
        reject(repo, ["golangci-lint", "run", "--enable-only", "recvcheck"], "recvcheck")
    finally:
        fixture.unlink()
print("lint dependency, constructor and receiver negative fixtures passed")
