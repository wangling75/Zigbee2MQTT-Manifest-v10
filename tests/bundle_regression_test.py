#!/usr/bin/env python3
"""Validate the published bundle's structural and semantic invariants.

The C++ differential test proves that the matcher selects the same definition
as the official resolver. These checks add the binary-layout and release
metadata guarantees that the ESP32 loader depends on.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = Path(os.environ.get("Z2M_BUNDLE", ROOT / "dist" / "z2m_bundle.candidate.bin"))
MANIFEST = Path(os.environ.get("Z2M_MANIFEST", ROOT / "dist" / "z2m_manifest.candidate.json"))
HEADER_SIZE = 128
INDEX_ENTRY_SIZE = 32


def u16(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<H", raw, offset)[0]


def u32(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<I", raw, offset)[0]


def main() -> int:
    raw = BUNDLE.read_bytes()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if raw[:4] != b"Z2MB":
        raise SystemExit("bundle magic is not Z2MB")
    if (u16(raw, 4), u16(raw, 6)) != (10, 10):
        raise SystemExit("bundle is not v10/v10")

    model_offset = u32(raw, 12)
    model_count = u32(raw, 16)
    fp_offset = u32(raw, 20)
    fp_count = u32(raw, 24)
    records_offset = u32(raw, 28)
    strings_offset = u32(raw, 32)
    constraints_offset = u32(raw, 76)
    constraints_count = u32(raw, 80)
    endpoint_offset = u32(raw, 84)
    endpoint_count = u32(raw, 88)
    cluster_offset = u32(raw, 92)
    cluster_count = u32(raw, 96)
    white_label_offset = u32(raw, 100)
    white_label_count = u32(raw, 104)
    vm_code_offset = u32(raw, 108)
    vm_code_size = u32(raw, 112)
    vm_version = u16(raw, 116)
    capabilities = u32(raw, 118)
    # Header layout: reserved starts at 84; VM metadata starts at 108.
    # record_data_size is reserved[36] (84+36), not the last u32.
    vm_code_offset = u32(raw, 108)
    vm_code_size = u32(raw, 112)
    vm_version = u16(raw, 116)
    capabilities = u32(raw, 118)
    record_data_size = u32(raw, 84 + 36)
    vm_program_count = u32(raw, 84 + 40)

    assert model_offset == HEADER_SIZE
    assert model_offset + model_count * INDEX_ENTRY_SIZE == fp_offset
    assert fp_offset + fp_count * INDEX_ENTRY_SIZE == endpoint_offset
    assert endpoint_offset + endpoint_count * 16 == cluster_offset
    assert cluster_offset + cluster_count * 2 == white_label_offset
    assert white_label_offset + white_label_count * 64 == constraints_offset
    assert constraints_offset + constraints_count * 56 == records_offset
    assert records_offset + record_data_size == vm_code_offset
    assert vm_code_offset + vm_code_size == strings_offset
    assert strings_offset <= len(raw) == u32(raw, 36)
    assert constraints_count >= fp_count
    assert vm_version == 1
    assert record_data_size > 0
    assert vm_program_count <= 65535
    assert vm_code_size % 12 == 0
    assert capabilities & 0x03FF == 0x03FF
    assert manifest["sha256"] == hashlib.sha256(raw).hexdigest()
    assert manifest["bytes"] == len(raw)
    assert manifest["device_count"] == u32(raw, 8)
    assert manifest["model_index_count"] == model_count
    assert manifest["fingerprint_index_count"] == fp_count
    assert manifest["fingerprint_constraint_count"] == constraints_count

    # Every model-index entry must point at a record whose fixed extension
    # header is present. This catches a truncated record table before a
    # gateway ever receives the bundle.
    for index in range(model_count):
        entry_offset = model_offset + index * INDEX_ENTRY_SIZE
        record_offset = u32(raw, entry_offset + 8)
        record_len = u32(raw, entry_offset + 12)
        assert record_len >= 80
        record_abs = records_offset + record_offset
        assert record_abs + record_len <= records_offset + record_data_size
        # RecordHeader is 20 bytes, RecordV8Extension follows at +20,
        # and RecordV9Extension follows at +28. Its vm_version field is
        # uint16 at +28+16 = +44.
        declared_offset = u32(raw, record_abs + 20)
        declared_count = u32(raw, record_abs + 24)
        assert u16(raw, record_abs + 44) == 1
        assert declared_count <= 256
        assert declared_offset + declared_count * 4 <= record_data_size

    print(
        "PASS: Z2MB v10 layout, all-probe bundle invariants, and manifest metadata "
        f"(devices={u32(raw, 8)} models={model_count} fingerprints={fp_count})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
