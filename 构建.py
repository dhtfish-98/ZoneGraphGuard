#!/usr/bin/env python3
# Copyright (c) 2026 dhtfish98
"""Stage project inputs in Build and invoke an ordinary packaging tool."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


EXCLUDED = {"Build", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".venv", ".tox", ".nox", "CMakeFiles"}


def relative(value):
    if not value or value.startswith("/") or "\\" in value or "\0" in value or any(p in {"", ".", "..", ".git"} for p in value.split("/")):
        raise ValueError("Invalid input path")
    return Path(value)


def copy_regular(source, destination):
    if source.is_symlink() or not source.is_file():
        raise ValueError("Only regular project input files can be staged")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def stage(root, directory, configuration):
    if directory.exists() or directory.is_symlink():
        raise ValueError("Stage already exists; use --build for a new independent output")
    directory.mkdir(parents=True)
    for base, dirs, files in os.walk(root, followlinks=False):
        path = Path(base)
        dirs[:] = [n for n in dirs if n not in EXCLUDED and not n.endswith((".egg-info", ".dist-info"))]
        # A private copy of metadata keeps git-based package checks bound to HEAD.
        # It is staging input under ignored Build, never part of a release upload.
        for name in files:
            source = path / name
            if name.endswith((".pyc", ".pyo")) or name == ".DS_Store":
                continue
            copy_regular(source, directory / source.relative_to(root))
    for item in configuration["restored_inputs"]:
        original = relative(item["original"])
        saved = root / relative(item["stored"])
        if saved.is_symlink() or hashlib.sha256(saved.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Saved input changed: " + str(saved))
        destination = directory / original
        if destination.exists():
            if destination.read_bytes() != saved.read_bytes():
                raise ValueError("Conflicting restored input")
        else:
            copy_regular(saved, destination)
    return directory


def environment(root):
    build = root / "Build"
    for rel in ("临时", "缓存/python", "缓存/pip", "缓存/npm", "缓存/ruff", "缓存/go", "缓存/go-mod", "缓存/go-path", "输出/go-bin", "缓存/cargo", "缓存/xdg", "缓存/ccache", "缓存/sccache"):
        (build / rel).mkdir(parents=True, exist_ok=True)
    return dict(os.environ, TMPDIR=str(build / "临时"), TMP=str(build / "临时"), TEMP=str(build / "临时"), PYTHONPYCACHEPREFIX=str(build / "缓存/python"), PIP_CACHE_DIR=str(build / "缓存/pip"), npm_config_cache=str(build / "缓存/npm"), RUFF_CACHE_DIR=str(build / "缓存/ruff"), GOCACHE=str(build / "缓存/go"), GOMODCACHE=str(build / "缓存/go-mod"), GOTMPDIR=str(build / "临时"), GOPATH=str(build / "缓存/go-path"), GOBIN=str(build / "输出/go-bin"), CARGO_HOME=str(build / "缓存/cargo"), XDG_CACHE_HOME=str(build / "缓存/xdg"), CCACHE_DIR=str(build / "缓存/ccache"), SCCACHE_DIR=str(build / "缓存/sccache"))


def main():
    parser = argparse.ArgumentParser(description="文档集中保存；每次在 Build 中暂存原布局并构建。")
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--stage", action="store_true")
    operation.add_argument("--build", action="store_true")
    parser.add_argument("--ci", action="store_true", help="固定暂存到 Build/源码，供一次性 CI 工作区使用")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    if (root / "Build").is_symlink():
        raise ValueError("Build must be a real directory")
    config = json.loads((root / "构建配置.json").read_text())
    env = environment(root)
    label = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = root / "Build" / "新构建" / label
    source = root / "Build/源码" if args.ci else output / "source"
    stage(root, source, config)
    if args.stage:
        print(json.dumps({"status": "STAGED_NO_BUILD_EXECUTED", "source": str(source)}, ensure_ascii=False))
        return 0
    output.mkdir(parents=True, exist_ok=True)
    packages = output / "发行"
    packages.mkdir()
    kind = config["kind"]
    if kind == "python":
        commands = [[sys.executable, "-m", "build", "--outdir", str(packages)]]
    elif kind == "python-wheel":
        commands = [[sys.executable, "-m", "build", "--wheel", "--outdir", str(packages)]]
    elif kind == "node":
        commands = [["npm", "pack", "--ignore-scripts", "--pack-destination", str(packages)]]
    elif kind == "cmake":
        binary = output / "编译"
        commands = [["cmake", "-S", str(source), "-B", str(binary), "-DCMAKE_BUILD_TYPE=Release"], ["cmake", "--build", str(binary), "--parallel", "2"], ["cmake", "--install", str(binary), "--prefix", str(output / "安装")]]
    elif kind == "rust":
        env["CARGO_TARGET_DIR"] = str(output / "编译")
        commands = [["cargo", "build", "--locked", "--manifest-path", config["cargo_manifest"]]]
    elif kind == "go":
        commands = [["go", "build", "-o", str(output / "编译") + "/", "./..."]]
    else:
        print(json.dumps({"status": "OPEN_MANUAL_ADAPTER", "source": str(source), "kind": kind}, ensure_ascii=False))
        return 3
    results = []
    for i, command in enumerate(commands, 1):
        log = output / f"{i:02}.log"
        with log.open("w") as stream:
            completed = subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
        results.append({"command": command, "exit_code": completed.returncode, "log": str(log)})
        if completed.returncode:
            break
    status = "PASS_BUILD_COMMANDS" if results and all(r["exit_code"] == 0 for r in results) else "FAIL"
    report = {"status": status, "source": str(source), "commands": results, "scope": "Build commands only; no project tests, installation to system applications, commit or publication."}
    (output / "build.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if status == "PASS_BUILD_COMMANDS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "ERROR", "reason": str(exc)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(2)
