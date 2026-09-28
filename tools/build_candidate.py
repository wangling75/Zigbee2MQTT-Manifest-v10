#!/usr/bin/env python3
"""Build, validate, and publish a candidate Z2M bundle.

The script is intentionally dependency-free and is used both locally and by
GitHub Actions. It keeps the published frozen IR untouched until every
candidate check has passed.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools" / "z2m_bundle_generator.mjs"
COMPILER = ROOT / "tools" / "z2m_binary_compiler.py"
VALIDATOR = ROOT / "tools" / "validate_bundle.py"
FROZEN = ROOT / "build_ir_frozen"
DIST = ROOT / "dist"
PUBLIC = ROOT / "public"
CANDIDATE_BUNDLE = DIST / "z2m_bundle.candidate.bin"
CANDIDATE_MANIFEST = DIST / "z2m_manifest.candidate.json"


def run(command: list[str], cwd: Path = ROOT,
        env: dict[str, str] | None = None) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)

def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def validate_candidate(bundle: Path, manifest: Path) -> dict:
    run([sys.executable, str(VALIDATOR), str(bundle), str(manifest)])
    return load_json(manifest)


def run_candidate_regressions(bundle: Path, manifest: Path) -> None:
    env = os.environ.copy()
    env["Z2M_BUNDLE"] = str(bundle)
    env["Z2M_MANIFEST"] = str(manifest)
    commands = [
        [sys.executable, "tests/bundle_regression_test.py"],
        [sys.executable, "tests/run_matcher_diff.py"],
    ]
    for command in commands:
        print("+", " ".join(command), flush=True)
        run(command, env=env)


def build_candidate(out_dir: Path, dist_dir: Path) -> tuple[Path, Path]:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    dist_dir.mkdir(parents=True, exist_ok=True)

    run(["node", str(GENERATOR), str(out_dir)])
    bundle = dist_dir / CANDIDATE_BUNDLE.name
    manifest = dist_dir / CANDIDATE_MANIFEST.name
    run([sys.executable, str(COMPILER), str(out_dir), str(bundle), str(manifest)])
    return bundle, manifest


def promote(candidate_ir: Path, candidate_bundle: Path,
            candidate_manifest: Path) -> dict:
    candidate_ir = candidate_ir.resolve()
    if candidate_ir == FROZEN.resolve():
        raise ValueError("candidate IR must not be the frozen IR directory")
    if FROZEN.exists():
        shutil.rmtree(FROZEN)
    shutil.copytree(candidate_ir, FROZEN)

    DIST.mkdir(parents=True, exist_ok=True)
    final_bundle = DIST / "z2m_bundle.bin"
    final_manifest = DIST / "z2m_manifest.json"
    shutil.copy2(candidate_bundle, final_bundle)

    published = load_json(candidate_manifest)
    published["bundle"] = "z2m_bundle.bin"
    write_json(final_manifest, published)
    # Validate the rewritten manifest against the exact bytes being served.
    validate_candidate(final_bundle, final_manifest)

    PUBLIC.mkdir(parents=True, exist_ok=True)
    (ROOT / "data").mkdir(parents=True, exist_ok=True)
    shutil.copy2(final_bundle, ROOT / "data" / "z2m_bundle.bin")
    shutil.copy2(final_bundle, PUBLIC / "z2m_bundle.bin")
    shutil.copy2(final_manifest, PUBLIC / "z2m_manifest.json")
    shutil.copy2(final_manifest, PUBLIC / "manifest.json")

    return load_json(final_manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--promote", action="store_true",
                        help="replace build_ir_frozen/dist/public after validation")
    parser.add_argument("--keep-candidate", action="store_true",
                        help="leave the candidate IR in build_ir_candidate")
    parser.add_argument("--candidate-dir", default=str(ROOT / "build_ir_candidate"))
    parser.add_argument("--candidate-ir", help="use an already-validated candidate IR directory")
    parser.add_argument("--candidate-bundle", help="use an already-validated candidate bundle")
    parser.add_argument("--candidate-manifest", help="use an already-validated candidate manifest")
    args = parser.parse_args()

    supplied = (args.candidate_ir, args.candidate_bundle, args.candidate_manifest)
    if args.promote and any(supplied):
        if not all(supplied):
            parser.error("--candidate-ir, --candidate-bundle and "
                         "--candidate-manifest must be supplied together")
        promoted = promote(Path(args.candidate_ir), Path(args.candidate_bundle), Path(args.candidate_manifest))
        print("PROMOTED", json.dumps(promoted, sort_keys=True))
        return 0

    candidate_dir = Path(args.candidate_dir)
    with tempfile.TemporaryDirectory(prefix="z2m-candidate-") as temporary:
        temp_dir = Path(temporary) / "ir"
        bundle, manifest = build_candidate(temp_dir, DIST)
        result = validate_candidate(bundle, manifest)
        run_candidate_regressions(bundle, manifest)
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.keep_candidate:
            if candidate_dir.exists():
                shutil.rmtree(candidate_dir)
            shutil.copytree(temp_dir, candidate_dir)
        if args.promote:
            promoted = promote(temp_dir, bundle, manifest)
            print("PROMOTED", json.dumps(promoted, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
