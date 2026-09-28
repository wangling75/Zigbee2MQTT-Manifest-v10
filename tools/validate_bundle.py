#!/usr/bin/env python3
"""Validate a Z2MB v10 binary bundle and its JSON manifest.

This is intentionally dependency-free so the same checks run locally, in
Docker, and in GitHub Actions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass

MAGIC = b"Z2MB"
FORMAT_VERSION = 10
IR_VERSION = 10
HEADER_SIZE = 128
INDEX_ENTRY_SIZE = 32
FINGERPRINT_CONSTRAINT_SIZE = 56
FINGERPRINT_ENDPOINT_SIZE = 16
SUPPORTED_CAPABILITIES = 0x03FF
REQUIRED_CAPABILITIES = 0x0100 | 0x0200


@dataclass(frozen=True)
class BundleHeader:
    magic: bytes
    version: int
    ir_version: int
    device_count: int
    model_offset: int
    model_count: int
    fingerprint_offset: int
    fingerprint_count: int
    records_offset: int
    strings_offset: int
    total_size: int
    crc: int
    payload_sha256: bytes
    constraints_offset: int
    constraints_count: int
    endpoint_offset: int
    endpoint_count: int
    cluster_offset: int
    cluster_count: int
    white_label_offset: int
    white_label_count: int
    vm_code_offset: int
    vm_code_size: int
    vm_version: int
    capabilities: int
    record_data_size: int
    vm_program_count: int


def _parse_header(raw: bytes) -> BundleHeader:
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"bundle is shorter than {HEADER_SIZE} bytes")
    values = struct.unpack_from("<4sHHIIIIIIIII32sII", raw, 0)
    reserved = struct.unpack_from("<IIIIIIIIIIII", raw, 84)
    vm = struct.unpack_from("<IIHHII", raw, 108)
    return BundleHeader(
        magic=values[0],
        version=values[1],
        ir_version=values[2],
        device_count=values[3],
        model_offset=values[4],
        model_count=values[5],
        fingerprint_offset=values[6],
        fingerprint_count=values[7],
        records_offset=values[8],
        strings_offset=values[9],
        total_size=values[10],
        crc=values[11],
        payload_sha256=values[12],
        constraints_offset=values[13],
        constraints_count=values[14],
        endpoint_offset=reserved[0],
        endpoint_count=reserved[1],
        cluster_offset=reserved[2],
        cluster_count=reserved[3],
        white_label_offset=reserved[4],
        white_label_count=reserved[5],
        vm_code_offset=vm[0],
        vm_code_size=vm[1],
        vm_version=vm[2],
        capabilities=vm[3],
        record_data_size=vm[4],
        vm_program_count=vm[5],
    )


def validate_bundle(bundle_path: str, manifest_path: str | None = None) -> dict:
    with open(bundle_path, "rb") as handle:
        raw = handle.read()
    header = _parse_header(raw)

    if header.magic != MAGIC:
        raise ValueError(f"invalid magic: {header.magic!r}")
    if (header.version, header.ir_version) != (FORMAT_VERSION, IR_VERSION):
        raise ValueError(
            f"unsupported bundle version: {header.version}/{header.ir_version}"
        )
    if header.total_size != len(raw):
        raise ValueError(
            f"declared size {header.total_size} does not match file size {len(raw)}"
        )
    if header.model_offset != HEADER_SIZE:
        raise ValueError(f"model table starts at {header.model_offset}, expected {HEADER_SIZE}")
    if header.device_count == 0 or header.model_count == 0 or header.fingerprint_count == 0:
        raise ValueError("bundle has an empty device/model/fingerprint table")

    expected_fingerprint = (
        header.model_offset + header.model_count * INDEX_ENTRY_SIZE
    )
    expected_endpoint = (
        header.fingerprint_offset + header.fingerprint_count * INDEX_ENTRY_SIZE
    )
    expected_cluster = expected_endpoint + header.endpoint_count * FINGERPRINT_ENDPOINT_SIZE
    expected_white_label = expected_cluster + header.cluster_count * 2
    expected_constraints = (
        expected_white_label + header.white_label_count * 64
    )
    expected_records = (
        expected_constraints
        + header.constraints_count * FINGERPRINT_CONSTRAINT_SIZE
    )
    expected_vm_code = header.records_offset + header.record_data_size
    expected_strings = header.vm_code_offset + header.vm_code_size

    if header.fingerprint_offset != expected_fingerprint:
        raise ValueError("model-index/fingerprint-index boundary mismatch")
    if header.endpoint_offset != expected_endpoint:
        raise ValueError("fingerprint-index/endpoint boundary mismatch")
    if header.cluster_offset != expected_cluster:
        raise ValueError("endpoint/cluster boundary mismatch")
    if header.white_label_offset != expected_white_label:
        raise ValueError("cluster/white-label boundary mismatch")
    if header.constraints_offset != expected_constraints:
        raise ValueError("white-label/constraint boundary mismatch")
    if header.records_offset != expected_records:
        raise ValueError("constraint/record boundary mismatch")
    if header.vm_code_offset != expected_vm_code:
        raise ValueError("record/VM-code boundary mismatch")
    if header.strings_offset != expected_strings:
        raise ValueError("VM-code/string boundary mismatch")
    if header.strings_offset > header.total_size:
        raise ValueError("string table extends beyond the bundle")
    if header.constraints_count < header.fingerprint_count:
        raise ValueError("fingerprint constraint table is incomplete")
    if header.record_data_size == 0 or header.vm_program_count > 65535:
        raise ValueError("invalid record/VM program metadata")
    if header.vm_code_size % 12 != 0:
        raise ValueError("VM code size is not aligned to 12-byte instructions")
    if header.vm_version != 1:
        raise ValueError(f"unsupported VM version: {header.vm_version}")
    if header.capabilities & ~SUPPORTED_CAPABILITIES:
        raise ValueError(
            f"bundle requires unsupported capability bits: "
            f"0x{header.capabilities & ~SUPPORTED_CAPABILITIES:04X}"
        )
    if (header.capabilities & REQUIRED_CAPABILITIES) != REQUIRED_CAPABILITIES:
        raise ValueError(
            f"bundle lacks required capability bits 0x0100/0x0200: "
            f"0x{header.capabilities:04X}"
        )

    payload_hash = hashlib.sha256(raw[HEADER_SIZE:]).digest()
    if payload_hash != header.payload_sha256:
        raise ValueError("embedded payload SHA-256 does not match")

    result = {
        "bundle": os.path.basename(bundle_path),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "device_count": header.device_count,
        "model_index_count": header.model_count,
        "fingerprint_index_count": header.fingerprint_count,
        "fingerprint_constraint_count": header.constraints_count,
        "fingerprint_endpoint_count": header.endpoint_count,
        "fingerprint_cluster_count": header.cluster_count,
        "white_label_count": header.white_label_count,
        "vm_version": header.vm_version,
        "vm_program_count": header.vm_program_count,
        "vm_code_size": header.vm_code_size,
        "required_capability_mask": header.capabilities,
    }

    if manifest_path:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        if manifest.get("format") != "z2m-binary-bundle-v10":
            raise ValueError(f"unexpected manifest format: {manifest.get('format')!r}")
        expected = {
            "bytes": len(raw),
            "sha256": result["sha256"],
            "device_count": header.device_count,
            "model_index_count": header.model_count,
            "fingerprint_index_count": header.fingerprint_count,
            "fingerprint_constraint_count": header.constraints_count,
        }
        for key, value in expected.items():
            if manifest.get(key) != value:
                raise ValueError(
                    f"manifest {key}={manifest.get(key)!r}, bundle has {value!r}"
                )
        if manifest.get("ir_version") != IR_VERSION:
            raise ValueError(
                f"manifest ir_version={manifest.get('ir_version')!r}, expected {IR_VERSION}"
            )
        result["manifest"] = os.path.basename(manifest_path)
        result["manifest_sha256"] = hashlib.sha256(
            json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="?", default="dist/z2m_bundle.bin")
    parser.add_argument("manifest", nargs="?", default="dist/z2m_manifest.json")
    parser.add_argument("--expect-sha256")
    parser.add_argument("--expect-size", type=int)
    parser.add_argument("--expect-devices", type=int)
    args = parser.parse_args()

    try:
        result = validate_bundle(args.bundle, args.manifest)
        if args.expect_sha256 and result["sha256"] != args.expect_sha256:
            raise ValueError(
                f"SHA-256 mismatch: {result['sha256']} != {args.expect_sha256}"
            )
        if args.expect_size is not None and result["bytes"] != args.expect_size:
            raise ValueError(f"size mismatch: {result['bytes']} != {args.expect_size}")
        if args.expect_devices is not None and result["device_count"] != args.expect_devices:
            raise ValueError(
                f"device count mismatch: {result['device_count']} != {args.expect_devices}"
            )
    except (OSError, ValueError, struct.error) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    print("PASS: Z2MB v10 layout, capabilities, VM metadata, and manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
