#!/usr/bin/env python3
"""
Z2M Binary Bundle Compiler v10.0 for ESP32 Gateway
Compiles Zigbee2MQTT device definitions into a compact, zero-RAM binary bundle
with dual sorted index tables (Model Hash + Fingerprint Hash) and a v6
fingerprint constraint table for O(log N) Flash binary search. The current
on-wire format is v10; older v5-v9 layouts remain loadable by firmware.
"""

import os
import sys
import json
import struct
import hashlib
from typing import List, Dict, Any
from collections import defaultdict

MAGIC = b"Z2MB"
FORMAT_VERSION = 10
IR_VERSION = 10
HEADER_SIZE = 128
INDEX_ENTRY_SIZE = 32
FINGERPRINT_CONSTRAINT_SIZE = 56
FINGERPRINT_FLAG_MANUFACTURER_CODE = 0x01
FINGERPRINT_FLAG_IEEE_ADDR = 0x02
FINGERPRINT_FLAG_ENDPOINTS = 0x04
FINGERPRINT_ENDPOINT_SIZE = 16
# v9 record extension and VM code region. Keep in sync with converter_types.h.
RECORD_V9_EXTENSION_SIZE = 20
RECORD_V10_BATTERY_EXTENSION_SIZE = 32
BATTERY_FLAG_ENABLED = 0x01
BATTERY_FLAG_PERCENTAGE = 0x02
BATTERY_FLAG_VOLTAGE = 0x04
BATTERY_FLAG_LOW_STATUS = 0x08
BATTERY_FLAG_DONT_DIVIDE_PERCENTAGE = 0x10
BATTERY_FLAG_TUYA_INVALID_DROP = 0x20
VM_INSTRUCTION_SIZE = 12
VM_VERSION = 1
VM_PROGRAM_ABSENT = 0xFFFFFFFF
VM_CAPABILITY_BASE = 0x0001
VM_CAPABILITY_TUYA = 0x0002
VM_CAPABILITY_ZCL_WRITE = 0x0004
VM_CAPABILITY_IGNORE = 0x0008
VM_CAPABILITY_STATIC_IGNORE = 0x0010
VM_CAPABILITY_TUYA_FIRST_DP = 0x0020
VM_CAPABILITY_TUYA_COMPOSITE_OMIT = 0x0040
VM_CAPABILITY_COMMAND_EVENT = 0x0080
VM_CAPABILITY_BATTERY_SEMANTICS = 0x0100
VM_CAPABILITY_IAS_SEMANTICS = 0x0200
RECORD_V9_FLAG_MULTI_ENDPOINT = 0x0001
# White-label matching uses the same fingerprint semantics as ZHC.
# Keep this fixed layout in sync with include/converter_types.h.
WHITE_LABEL_SIZE = 64
# Index flags. Keep these in sync with include/converter_types.h.
FLAG_AMBIGUOUS_MODEL = 0x0020
FLAG_AMBIGUOUS_FINGERPRINT = 0x0040
FLAG_MULTI_ENDPOINT = 0x0004
FLAG_MODEL_FALLBACK = 0x0080
FLAG_MODEL_EXACT_KEY = 0x0100
FLAG_MODEL_NORMALIZED_KEY = 0x0200
FLAG_HAS_ZIGBEE_MODEL = 0x0400

# Datatype enum
DATATYPE_MAP = {
    "bool": 0,
    "uint8": 1,
    "int16": 2,
    "uint16": 3,
    "int32": 4,
    "uint32": 5,
    "enum8": 6,
    "raw": 7,
    "string": 8,
    "single_prec": 9,
    "double_prec": 10,
    "uint48": 11,
    "int24": 12,
    "bitmap16": 13,
    "value": 14
}

# ZCL wire datatypes. These are intentionally separate from DATATYPE_MAP:
# fromZigbee stores an internal enum, while v4 toZigbee writes must carry
# the real ZCL datatype byte used by Write Attributes.
ZCL_DATATYPE_MAP = {
    "no_data": 0x00,
    "bool": 0x10,
    "bitmap8": 0x18,
    "uint8": 0x20,
    "uint16": 0x21,
    "uint24": 0x22,
    "uint32": 0x23,
    "uint40": 0x24,
    "uint48": 0x25,
    "int8": 0x28,
    "int16": 0x29,
    "int24": 0x2A,
    "int32": 0x2B,
    "enum8": 0x30,
    "enum16": 0x31,
    "single_prec": 0x38,
    "double_prec": 0x39,
}

# Opcode enum
OP_READ_ATTR = 0x01
OP_WRITE_ATTR = 0x02
OP_COMMAND = 0x03
OP_REPORT_ATTR = 0x04
OP_BIND_CLUSTER = 0x05
OP_TUYA_DP = 0x06
OP_TRANSFORM = 0x07
OP_MAP_ENUM = 0x08
OP_BITFIELD = 0x09
OP_DYNAMIC_ENDPOINT = 0x0A
OP_COMMAND_EVENT = 0x0C

COMMAND_EVENT_KIND = {
    "literal": 1,
    "arm": 2,
    "move_to_level": 3,
    "move": 4,
    "step": 5,
    "color_temp_move": 6,
    "color_temp_step": 7,
    "color_temp": 8,
    "color_xy": 9,
    "enhanced_hue_sat": 10,
    "hue_sat": 11,
    "hue_step": 12,
    "saturation_step": 13,
    "color_loop": 14,
    "hue_move": 15,
    "saturation": 16,
    "hue": 17,
    "state_on": 18,
    "state_off": 19,
    "ewelink": 20,
    "ias_action": 21,
    "ignore": 22,
}
OP_IGNORE = 0x0B


def fnv1a_32(text: str) -> int:
    """Standard FNV-1a 32-bit hash for fast case-insensitive matching."""
    if not text:
        return 0
    h = 0x811C9DC5
    for b in text.lower().encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def _normalize_model_key(value: Any) -> str:
    """Mirror ZHC normalizeModelID without changing the exact-key path."""
    text = str(value or "")
    nul = text.find("\x00")
    if nul >= 0:
        text = text[:nul]
    return text.strip().lower()


def required_capability_names(mask: int) -> List[str]:
    names = []
    for bit, name in (
        (VM_CAPABILITY_BASE, "base"),
        (VM_CAPABILITY_TUYA, "tuya"),
        (VM_CAPABILITY_ZCL_WRITE, "zcl_write"),
        (VM_CAPABILITY_IGNORE, "ignore"),
        (VM_CAPABILITY_STATIC_IGNORE, "static_ignore"),
        (VM_CAPABILITY_TUYA_FIRST_DP, "tuya_first_dp_rule"),
        (VM_CAPABILITY_TUYA_COMPOSITE_OMIT, "tuya_composite_omit"),
    (VM_CAPABILITY_COMMAND_EVENT, "command_event"),
    (VM_CAPABILITY_BATTERY_SEMANTICS, "battery_semantics"),
    (VM_CAPABILITY_IAS_SEMANTICS, "ias_semantics"),
    ):
        if mask & bit:
            names.append(name)
    return names


def category_to_enum(cat: str) -> int:
    mapping = {
        "generic_device": 0,
        "on_off_light": 1,
        "dimmable_light": 2,
        "color_light": 3,
        "on_off_plugin_unit": 4,
        "on_off_switch": 5,
        "temp_sensor": 6,
        "humidity_sensor": 7,
        "contact_sensor": 8,
        "occupancy_sensor": 9,
        "light_sensor": 10,
        "water_leak_sensor": 11,
        "smoke_sensor": 12,
        "thermostat": 13,
        "window_covering": 14,
        "door_lock": 15
,
        "carbon_monoxide_sensor": 16,
        "gas_sensor": 17,
        "vibration_sensor": 18,
        "remote_control": 19
    }
    return mapping.get(cat.lower(), 0)


def to_int(val, default=0) -> int:
    if val is None:
        return default
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val:
            return default
        try:
            return int(val, 0)
        except Exception:
            try:
                return int(float(val))
            except Exception:
                return default
    try:
        return int(val)
    except Exception:
        return default


def to_float(val, default=1.0) -> float:
    if val is None:
        return default
    try:
        return float(val)
    except Exception:
        return default


def optional_int(val: Any) -> int:
    """Return -1 for an absent fingerprint numeric constraint."""
    if val is None or (isinstance(val, str) and not val.strip()):
        return -1
    return to_int(val, -1)


class BinaryBundleBuilderV4:
    def __init__(self):
        self.records = []
        self.model_index_entries = []
        self.fp_index_entries = []
        self.string_table = bytearray(b"\x00")  # 0 is empty string
        self.string_map = {"": 0}
        self.model_records = defaultdict(set)
        self.fingerprint_records = defaultdict(set)
        self.fingerprint_constraints = []
        self.white_label_entries = []
        self.fingerprint_endpoints = []
        self.fingerprint_clusters = []
        self.index_collisions = []
        self.vm_programs = []
        self.vm_program_offsets = {}

    @staticmethod
    def _model_keys(dev: Dict[str, Any]) -> List[str]:
        # MODELS_INDEX contains two distinct lookup classes:
        #   * the exact lower-cased key returned by the first lookup
        #   * the NUL/whitespace-normalized fallback key
        # Never merge them with strip(): some devices genuinely have NUL or
        # trailing-space model IDs and ZHC only falls back after an exact miss.
        exact = BinaryBundleBuilderV4._flag_model_keys(dev, "exactModels")
        normalized = BinaryBundleBuilderV4._flag_model_keys(dev, "normalizedModels")
        # Upstream MODELS_INDEX contains both the exact lower-cased key and
        # the NUL/whitespace-normalized fallback key. Both remain addressable;
        # the runtime decides which lookup class is used.
        keys = exact | normalized
        if keys:
            return sorted(keys)
        raw_models = dev.get("models")
        if not isinstance(raw_models, list) or not raw_models:
            raw_models = [dev.get("model", "")]
        return sorted({str(m or "").lower() for m in raw_models if str(m or "")})

    @staticmethod
    def _fallback_model_keys(dev: Dict[str, Any]) -> List[str]:
        raw_models = dev.get("fallbackModels")
        if not isinstance(raw_models, list):
            return BinaryBundleBuilderV4._model_keys(dev)
        return sorted({str(m or "").lower() for m in raw_models if str(m or "")})

    @staticmethod
    def _fingerprint_keys(dev: Dict[str, Any]) -> List[str]:
        raw_fps = dev.get("fingerprints")
        if not isinstance(raw_fps, list):
            return []
        keys = set()
        for fp in raw_fps:
            if not isinstance(fp, dict):
                continue
            keys.update(BinaryBundleBuilderV4._fingerprint_aliases(dev, fp))
        return sorted(keys)

    @staticmethod
    def _fingerprint_key(fp: Dict[str, Any]) -> str:
        # ZHC compares fingerprint modelID/manufacturerName with strict ===.
        # Only lower-case for the index hash; never trim or remove NULs.
        mfg = str(fp.get("manufacturerName", "") or "").lower()
        model = str(fp.get("modelID", "") or "").lower()
        return f"{mfg}|{model}" if (mfg or model) else ""

    @staticmethod
    def _model_priority(dev: Dict[str, Any], model_key: str, default: int = 0x7FFF) -> int:
        priorities = dev.get("modelPriority")
        if not isinstance(priorities, dict):
            return default
        key = str(model_key or "").lower()
        for candidate, value in priorities.items():
            if str(candidate or "").lower() == key:
                return to_int(value, default)
        return default

    @staticmethod
    def _flag_model_keys(dev: Dict[str, Any], field: str) -> set:
        raw_keys = dev.get(field)
        if not isinstance(raw_keys, list):
            return set()
        return {
            str(key or "").lower()
            for key in raw_keys
            if str(key or "")
        }

    @staticmethod
    def _fingerprint_aliases(dev: Dict[str, Any], fp: Dict[str, Any]) -> List[str]:
        """Return index keys for optional fingerprint fields.

        ZHC fingerprints may omit manufacturerName or modelID. A model-only
        fingerprint is queried through the empty-manufacturer key; a
        manufacturer-only fingerprint is expanded over the definition's
        zigbeeModel candidates because ZHC first selects candidates by modelID.
        """
        mfg = str(fp.get("manufacturerName", "") or "").lower()
        model = str(fp.get("modelID", "") or "").lower()
        if mfg and model:
            return [f"{mfg}|{model}"]
        if model:
            return [f"|{model}"]
        if mfg:
            return [f"{mfg}|{model_key}" for model_key in BinaryBundleBuilderV4._model_keys(dev)]
        # Fingerprints may constrain only endpoints/metadata. ZHC indexes
        # the definition through zigbeeModel even when the fingerprint itself
        # omits modelID/manufacturerName (IKEA KAJPLATS). Those constraints
        # still have to be attached to each official model key.
        return [f"|{model_key}" for model_key in BinaryBundleBuilderV4._model_keys(dev)]

    @staticmethod
    def _endpoint_identity(raw_endpoints: Any):
        if not isinstance(raw_endpoints, list):
            return ()
        result = []
        for ep in raw_endpoints:
            if not isinstance(ep, dict):
                continue
            def cluster_tuple(value):
                if not isinstance(value, list):
                    return None
                return tuple(to_int(c, 0) & 0xFFFF for c in value)
            result.append((
                to_int(ep.get("ID"), -1),
                optional_int(ep.get("profileID")),
                optional_int(ep.get("deviceID")),
                cluster_tuple(ep.get("inputClusters")),
                cluster_tuple(ep.get("outputClusters")),
            ))
        return tuple(result)

    @staticmethod
    def _fingerprint_constraints(dev: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return every distinct fingerprint constraint in upstream order."""
        raw_fps = dev.get("fingerprints")
        if not isinstance(raw_fps, list):
            return []
        constraints: List[Dict[str, Any]] = []
        for fp in raw_fps:
            if not isinstance(fp, dict):
                continue
            keys = BinaryBundleBuilderV4._fingerprint_aliases(dev, fp)
            if not keys:
                continue
            raw_mfg_code = fp.get("manufacturerID", fp.get("manufacturerCode"))
            mfg_code_defined = raw_mfg_code is not None and str(raw_mfg_code).strip() != ""
            for key in keys:
                alias_model = key.split("|", 1)[1] if "|" in key else ""
                model_priority = BinaryBundleBuilderV4._model_priority(dev, alias_model)
                # One official fingerprint may expand into several lookup
                # aliases. Each alias occurrence needs its own constraint row;
                # deduplicating by identity drops endpoint/IEEE constraints.
                manufacturer_name = str(fp.get("manufacturerName", "") or "")
                model_id = str(fp.get("modelID", "") or "")
                ieee_addr = str(fp.get("ieeeAddr", "") or "")
                endpoints = fp.get("endpoints") if isinstance(fp.get("endpoints"), list) else None

                constraints.append({
                    "key": key,
                    "manufacturer_name": manufacturer_name,
                    "model_id": model_id,
                    "manufacturer_code": to_int(raw_mfg_code, 0) & 0xFFFF,
                    "manufacturer_code_defined": mfg_code_defined,
                    "ieee_addr": ieee_addr,
                    "endpoints": endpoints,
                    "date_code": str(fp.get("dateCode", "") or ""),
                    "software_build_id": str(fp.get("softwareBuildID", "") or ""),
                    "type": str(fp.get("type", "") or ""),
                    "power_source": str(fp.get("powerSource", "") or ""),
                    "priority": to_int(fp.get("priority", 0)),
                    "application_version": optional_int(fp.get("applicationVersion")),
                    "hardware_version": optional_int(fp.get("hardwareVersion")),
                    "stack_version": optional_int(fp.get("stackVersion")),
                    "zcl_version": optional_int(fp.get("zclVersion")),
                    "model_priority": model_priority,
                    "source_order": len(constraints),
                })
        return constraints

    def _append_fingerprint_endpoints(self, endpoint_specs):
        """Append an ordered endpoint constraint and return (offset, count)."""
        if endpoint_specs is None:
            return 0, 0
        if not isinstance(endpoint_specs, list):
            raise ValueError("fingerprint endpoints must be a list")
        endpoint_offset = len(self.fingerprint_endpoints)
        if endpoint_offset > 0xFFFF or len(endpoint_specs) > 0xFF:
            raise ValueError("fingerprint endpoint table exceeds v6 limits")

        for endpoint_spec in endpoint_specs:
            if not isinstance(endpoint_spec, dict):
                raise ValueError("fingerprint endpoint must be an object")
            endpoint_flags = 0
            profile_id = 0xFFFF
            device_id = 0xFFFF
            if endpoint_spec.get("profileID") is not None:
                endpoint_flags |= 0x01
                profile_id = to_int(endpoint_spec.get("profileID"), 0xFFFF) & 0xFFFF
            if endpoint_spec.get("deviceID") is not None:
                endpoint_flags |= 0x02
                device_id = to_int(endpoint_spec.get("deviceID"), 0xFFFF) & 0xFFFF
            input_clusters = endpoint_spec.get("inputClusters")
            output_clusters = endpoint_spec.get("outputClusters")
            input_offset = len(self.fingerprint_clusters)
            if isinstance(input_clusters, list):
                endpoint_flags |= 0x04
                self.fingerprint_clusters.extend(to_int(c, 0) & 0xFFFF for c in input_clusters)
            output_offset = len(self.fingerprint_clusters)
            if isinstance(output_clusters, list):
                endpoint_flags |= 0x08
                self.fingerprint_clusters.extend(to_int(c, 0) & 0xFFFF for c in output_clusters)
            if len(self.fingerprint_clusters) > 0xFFFF:
                raise ValueError("fingerprint cluster table exceeds v6 limits")
            self.fingerprint_endpoints.append(struct.pack(
                "<HHHHHHBBH",
                input_offset,
                len(input_clusters) if isinstance(input_clusters, list) else 0,
                output_offset,
                len(output_clusters) if isinstance(output_clusters, list) else 0,
                profile_id,
                device_id,
                to_int(endpoint_spec.get("ID"), 0) & 0xFF,
                endpoint_flags,
                0,
            ))
        return endpoint_offset, len(endpoint_specs)

    def _prescan_records(self):
        self.model_records.clear()
        self.fingerprint_records.clear()
        self.index_collisions.clear()

        for rec_idx, dev in enumerate(self.records):
            for model in self._model_keys(dev):
                self.model_records[model].add(rec_idx)
            for fp_key in self._fingerprint_keys(dev):
                self.fingerprint_records[fp_key].add(rec_idx)

        for kind, records in (("model", self.model_records), ("fingerprint", self.fingerprint_records)):
            by_hash = defaultdict(set)
            for raw_key in records:
                by_hash[fnv1a_32(raw_key)].add(raw_key)
            for key_hash, raw_keys in by_hash.items():
                if len(raw_keys) > 1:
                    self.index_collisions.append({
                        "kind": kind,
                        "hash": f"{key_hash:08x}",
                        "keys": sorted(raw_keys),
                    })

        if self.index_collisions:
            details = "; ".join(
                f"{item['kind']} {item['hash']}: {', '.join(item['keys'])}"
                for item in self.index_collisions
            )
            raise ValueError(f"FNV1a-32 index collision detected: {details}")

    def _stats(self) -> Dict[str, Any]:
        ambiguous_models = {
            fnv1a_32(model)
            for model, records in self.model_records.items()
            if len(records) > 1
        }
        ambiguous_fingerprints = {
            fnv1a_32(fp_key)
            for fp_key, records in self.fingerprint_records.items()
            if len(records) > 1
        }
        return {
            "ambiguous_model_count": len(ambiguous_models),
            "duplicate_fingerprint_count": len(ambiguous_fingerprints),
            "model_hash_collision_count": sum(1 for c in self.index_collisions if c["kind"] == "model"),
            "fingerprint_hash_collision_count": sum(1 for c in self.index_collisions if c["kind"] == "fingerprint"),
            "_ambiguous_model_hashes": ambiguous_models,
            "_ambiguous_fingerprint_hashes": ambiguous_fingerprints,
        }

    def add_string(self, s: str) -> int:
        if not s:
            return 0
        if s in self.string_map:
            return self.string_map[s]
        s_bytes = s.encode("utf-8")
        if len(s_bytes) > 0xFFFF:
            raise ValueError("v10 string exceeds the 16-bit length prefix")
        offset = len(self.string_table)
        # v7+ strings are length-prefixed, not NUL-terminated. Offset zero is
        # reserved so it can keep meaning "unconstrained".
        self.string_table.extend(struct.pack("<H", len(s_bytes)))
        self.string_table.extend(s_bytes)
        self.string_map[s] = offset
        return offset

    def add_record(self, dev: Dict[str, Any]):
        self.records.append(dev)

    def _vm_program_bytes(self, dev: Dict[str, Any], field: str) -> bytes:
        program = dev.get(field)
        if not isinstance(program, list) or not program:
            return b""
        encoded = bytearray()
        for instruction in program:
            if not isinstance(instruction, dict):
                raise ValueError(f"{field} instruction must be an object")
            encoded.extend(struct.pack(
                "<HHII",
                to_int(instruction.get("opcode", 0)) & 0xFFFF,
                to_int(instruction.get("flags", 0)) & 0xFFFF,
                to_int(instruction.get("a", 0)) & 0xFFFFFFFF,
                to_int(instruction.get("b", 0)) & 0xFFFFFFFF,
            ))
        return bytes(encoded)

    def _register_vm_program(self, encoded: bytes):
        if not encoded:
            return VM_PROGRAM_ABSENT, 0
        if len(encoded) % VM_INSTRUCTION_SIZE != 0:
            raise ValueError("VM program size is not instruction-aligned")
        if encoded in self.vm_program_offsets:
            offset = self.vm_program_offsets[encoded]
        else:
            offset = sum(len(program) for program in self.vm_programs)
            if offset > 0xFFFFFFFF:
                raise ValueError("VM code region exceeds 32-bit limit")
            self.vm_program_offsets[encoded] = offset
            self.vm_programs.append(encoded)
        return offset, len(encoded)

    def build(self, out_bin_path: str) -> Dict[str, Any]:
        required_capabilities = VM_CAPABILITY_BASE
        self._prescan_records()
        stats = self._stats()
        for dev in self.records:
            for rule in dev.get("fromZigbee", []) or []:
                if not isinstance(rule, dict):
                    continue
                op = str(rule.get("op", ""))
                if op == "IGNORE":
                    required_capabilities |= VM_CAPABILITY_IGNORE | VM_CAPABILITY_STATIC_IGNORE
                elif op == "COMMAND_EVENT":
                    required_capabilities |= VM_CAPABILITY_COMMAND_EVENT
            battery = dev.get("batterySemantics")
            if isinstance(battery, dict) and battery.get("enabled") is True:
                required_capabilities |= VM_CAPABILITY_BATTERY_SEMANTICS
            for rule in dev.get("fromZigbee", []) or []:
                if isinstance(rule, dict) and to_int(rule.get("cluster", 0)) == 0x0500 and rule.get("target"):
                    required_capabilities |= VM_CAPABILITY_IAS_SEMANTICS
            for rule in dev.get("toZigbee", []) or []:
                if isinstance(rule, dict) and str(rule.get("op", "")) == "WRITE_ATTRIBUTE":
                    required_capabilities |= VM_CAPABILITY_ZCL_WRITE
            tuya_dps = dev.get("tuyaDatapoints", []) or []
            if tuya_dps:
                required_capabilities |= VM_CAPABILITY_TUYA
                if any(isinstance(dp, dict) and dp.get("inboundUnsupported") is True for dp in tuya_dps):
                    required_capabilities |= (VM_CAPABILITY_TUYA_FIRST_DP |
                                             VM_CAPABILITY_TUYA_COMPOSITE_OMIT)
        self.required_capabilities = required_capabilities
        ambiguous_model_hashes = stats["_ambiguous_model_hashes"]
        ambiguous_fingerprint_hashes = stats["_ambiguous_fingerprint_hashes"]

        self.model_index_entries.clear()
        self.fp_index_entries.clear()
        data_buffer = bytearray()
        record_map = []  # (rec_offset, rec_len)

        for rec_idx, dev in enumerate(self.records):
            rec_start = len(data_buffer)

            model = dev.get("model", "")
            vendor = dev.get("vendor", "")
            desc = dev.get("description", "")
            category = dev.get("category", "")
            cat_enum = category_to_enum(category)
            flags = dev.get("flags", 0)

            model_off = self.add_string(model)
            vendor_off = self.add_string(vendor)
            desc_off = self.add_string(desc)

            endpoints = dev.get("endpoints", {})
            endpoint_capabilities = dev.get("endpointCapabilities", {})
            if not isinstance(endpoint_capabilities, dict):
                endpoint_capabilities = {}
            endpoint_capability_bits = dev.get("endpointCapabilityBits", {})
            if not isinstance(endpoint_capability_bits, dict):
                endpoint_capability_bits = {}
            fz_rules = dev.get("fromZigbee", [])
            tz_rules = dev.get("toZigbee", [])
            tuya_dps = dev.get("tuyaDatapoints", [])
            cfg = dev.get("configure", {})
            binds = cfg.get("binds", [])
            reporting = cfg.get("reporting", [])

            # 1. Record Header (20 bytes)
            rec_hdr = struct.pack(
                "<IIIBBBBBBBB",
                model_off,
                vendor_off,
                desc_off,
                cat_enum,
                flags & 0xFF,
                min(len(fz_rules), 255),
                min(len(tz_rules), 255),
                min(len(tuya_dps), 255),
                min(len(endpoints), 255),
                min(len(binds), 255),
                min(len(reporting), 255)
            )
            data_buffer.extend(rec_hdr)

            # v8 record extension: exact-case declared zigbeeModel list.
            # ZHC's final fallback compares these strings with strict equality.
            declared_models = dev.get("declaredModels", [])
            if not isinstance(declared_models, list):
                declared_models = []
            declared_offsets = [self.add_string(str(m or "")) for m in declared_models if str(m or "")]
            declared_offset = (len(data_buffer) + 8 + RECORD_V9_EXTENSION_SIZE +
                               RECORD_V10_BATTERY_EXTENSION_SIZE)
            data_buffer.extend(struct.pack("<II", declared_offset, len(declared_offsets)))

            from_program = self._vm_program_bytes(dev, "fromVm")
            to_program = self._vm_program_bytes(dev, "toVm")
            from_program_offset, from_program_size = self._register_vm_program(from_program)
            to_program_offset, to_program_size = self._register_vm_program(to_program)
            multi_endpoint = dev.get("multiEndpoint") is True
            multi_endpoint_skip = dev.get("multiEndpointSkip", [])
            if not isinstance(multi_endpoint_skip, list):
                multi_endpoint_skip = []
            record_flags = RECORD_V9_FLAG_MULTI_ENDPOINT if multi_endpoint else 0
            data_buffer.extend(struct.pack(
                "<IIIIHH",
                from_program_offset,
                from_program_size,
                to_program_offset,
                to_program_size,
                VM_VERSION,
                0,
            ))
            # Patch the flags field before the v10 fixed extension is
            # appended. The v9 header is at the end of this 20-byte block.
            v9_flags_off = len(data_buffer) - 2
            battery = dev.get("batterySemantics")
            if not isinstance(battery, dict) or battery.get("enabled") is not True:
                battery = None
            if battery is not None:
                exceptions = battery.get("exceptions")
                if not isinstance(exceptions, list):
                    exceptions = []
                battery_flags = BATTERY_FLAG_ENABLED
                if battery.get("percentage") is True:
                    battery_flags |= BATTERY_FLAG_PERCENTAGE
                if battery.get("voltage") is True:
                    battery_flags |= BATTERY_FLAG_VOLTAGE
                if battery.get("lowStatus") is True:
                    battery_flags |= BATTERY_FLAG_LOW_STATUS
                if battery.get("dontDividePercentage") is True:
                    battery_flags |= BATTERY_FLAG_DONT_DIVIDE_PERCENTAGE
                if to_int(battery.get("dropPercentageValue"), 0) > 0:
                    battery_flags |= BATTERY_FLAG_TUYA_INVALID_DROP
                data_buffer.extend(struct.pack(
                    "<BBBBfffI12s",
                    battery_flags,
                    to_int(battery.get("curve"), 0) & 0xFF,
                    to_int(battery.get("dropPercentageValue"), 0) & 0xFF,
                    to_int(battery.get("dropVoltageThreshold"), 0) & 0xFF,
                    to_float(battery.get("minVoltage"), 0.0),
                    to_float(battery.get("maxVoltage"), 0.0),
                    to_float(battery.get("voltageOffset"), 0.0),
                    self.add_string("\n".join(str(v) for v in exceptions)),
                    b"\x00" * 12,
                ))
            else:
                # v10 records have a fixed layout. Even definitions without
                # battery semantics must carry a zeroed 32-byte extension.
                data_buffer.extend(b"\x00" * RECORD_V10_BATTERY_EXTENSION_SIZE)
            for str_offset in declared_offsets:
                data_buffer.extend(struct.pack("<I", str_offset))
            
            if multi_endpoint:
                # Header plus the skip string-offset table, both local to this
                # record. The table immediately follows the 8-byte header.
                skip_offsets = [self.add_string(str(v)) for v in multi_endpoint_skip]
                # Metadata offsets are relative to the records section, like
                # declared_models_offset. The skip table follows the header.
                skip_off = len(data_buffer) + 8
                data_buffer.extend(struct.pack("<IHH", skip_off, len(skip_offsets), 0))
                for str_offset in skip_offsets:
                    data_buffer.extend(struct.pack("<I", str_offset))
                struct.pack_into("<H", data_buffer, v9_flags_off, record_flags)

            # 2. Endpoints (4 bytes each: ep_id, pad, name string offset)
            for ep_name, ep_id in endpoints.items():
                name_off = min(self.add_string(str(ep_name)), 65535)
                cap = to_int(endpoint_capabilities.get(str(ep_name), 0), 0)
                if not cap:
                    cap = to_int(endpoint_capability_bits.get(str(to_int(ep_id, 1)), 0), 0)
                data_buffer.extend(struct.pack("<BBH", to_int(ep_id, 1), cap & 0xFF, name_off))

            # 3. fromZigbee IR rules (20 bytes each)
            for fz in fz_rules:
                op = OP_READ_ATTR
                if fz.get("op") == "REPORT_ATTRIBUTE":
                    op = OP_REPORT_ATTR
                elif fz.get("op") == "TRANSFORM":
                    op = OP_TRANSFORM
                elif fz.get("op") == "MAP_ENUM":
                    op = OP_MAP_ENUM
                elif fz.get("op") == "IGNORE":
                    op = OP_IGNORE
                elif fz.get("op") == "COMMAND_EVENT":
                    op = OP_COMMAND_EVENT

                dtype = DATATYPE_MAP.get(fz.get("datatype", "uint16"), 1)
                cl = to_int(fz.get("cluster", 0))
                if op == OP_COMMAND_EVENT:
                    at = to_int(fz.get("cmd", 0))
                    dtype = COMMAND_EVENT_KIND.get(str(fz.get("kind", "literal")), 1)
                else:
                    at = to_int(fz.get("attr", 0))
                ep = to_int(fz.get("endpoint", 0))
                target = str(fz.get("target", ""))
                tgt_off = self.add_string(target)
                scale = to_float(fz.get("scale", 1.0))
                offset = to_float(fz.get("offset", 0.0))
                if op == OP_COMMAND_EVENT and fz.get("value"):
                    value_off = self.add_string(str(fz.get("value", "")))
                    scale = float(value_off)
                if op == OP_COMMAND_EVENT and fz.get("field"):
                    field_off = self.add_string(str(fz.get("field", "")))
                    offset = float(field_off)
                # v5 uses the otherwise reserved byte for the IAS Alarm bit.
                # Zero remains the historical Alarm 1 default.
                # pad8 is a small flags field, not a free-form byte:
                #   bits 0..3: IAS alarm bit index (0 or 1)
                #   bit 4:     ZHC meta.coverInverted
                # Older v5 bundles have zero here, preserving Alarm 1 and
                # the default non-inverted cover interpretation.
                pad8 = to_int(fz.get("iasBit", 0)) & 0x0F
                if fz.get("coverInverted"):
                    pad8 |= 0x10
                if fz.get("iasInvert"):
                    pad8 |= 0x20

                rule_bytes = struct.pack("<BBHHBBIff", op, dtype, cl, at, ep, pad8, tgt_off, scale, offset)
                data_buffer.extend(rule_bytes)

            # 4. toZigbee IR rules (16 bytes each)
            for tz in tz_rules:
                op = OP_COMMAND if tz.get("op") == "COMMAND" else OP_WRITE_ATTR
                ep = to_int(tz.get("endpoint", 0))
                cl = to_int(tz.get("cluster", 0))
                cmd = to_int(tz.get("cmd") or tz.get("attr", 0))
                cmd_on = to_int(tz.get("cmd_on", 1))
                cmd_off = to_int(tz.get("cmd_off", 0))
                tgt_off = self.add_string(str(tz.get("target", "")))
                scale = to_float(tz.get("scale", 1.0))

                # v4 carries the ZCL datatype so writes are encoded correctly.
                dtype = ZCL_DATATYPE_MAP.get(str(tz.get("datatype", "int16")).lower(), ZCL_DATATYPE_MAP["int16"])
                tz_bytes = struct.pack(
                    "<BBHHBBIfBBBB",
                    op, ep, cl, cmd, cmd_on, cmd_off, tgt_off, scale,
                    dtype, 0, 0, 0
                )
                data_buffer.extend(tz_bytes)

            # 5. Tuya DP rules (20 bytes each)
            for dp in tuya_dps:
                dp_id = to_int(dp.get("dp", 0))
                dtype_str = dp.get("datatype", "value")
                dtype = 0  # value
                if dtype_str == "enum":
                    dtype = 1
                elif dtype_str == "bool":
                    dtype = 2
                elif dtype_str == "raw":
                    dtype = 3
                elif dtype_str == "string":
                    dtype = 4

                # Bit 7 is the v8c inbound-unsupported flag. The low bits stay
                # the official wire type so toZigbee keeps the correct encoding
                # for duplicate rows that only participate in writes.
                if dp.get("inboundUnsupported") is True:
                    dtype |= 0x80

                tgt_off = self.add_string(str(dp.get("target", "")))
                scale = to_float(dp.get("scale", 1.0))
                offset = to_float(dp.get("offset", 0.0))

                map_obj = dp.get("map")
                map_str = json.dumps(map_obj) if map_obj else ""
                map_off = self.add_string(map_str) if map_str else 0

                # Byte 2 is the Tuya cluster command. Older v5 generators
                # wrote zero here, which is the ZHC default (dataRequest).
                send_command = 0x04 if to_int(dp.get("sendCommand", 0)) == 0x04 else 0x00
                dp_bytes = struct.pack("<BBBBIffI", dp_id, dtype, send_command, 0,
                                         tgt_off, scale, offset, map_off)
                data_buffer.extend(dp_bytes)

            # 6. Reporting config (8 bytes each)
            for rep in reporting:
                cl = to_int(rep.get("cluster", 0))
                at = to_int(rep.get("attr", 0))
                min_i = to_int(rep.get("min", 10))
                max_i = to_int(rep.get("max", 3600))
                data_buffer.extend(struct.pack("<HHHH", cl, at, min_i, max_i))

            # 7. Binds (2 bytes each)
            for b in binds:
                data_buffer.extend(struct.pack("<H", to_int(b, 0)))

            # 8. White-label overrides. The base definition is selected
            # first, then ZHC applies the first whiteLabel entry whose
            # fingerprint matches.
            white_labels = dev.get("whiteLabels", [])
            if not isinstance(white_labels, list):
                white_labels = []
            for white_label in white_labels:
                if not isinstance(white_label, dict):
                    continue
                fp_specs = white_label.get("fingerprint")
                if not isinstance(fp_specs, list) or not fp_specs:
                    continue
                for fp_spec in fp_specs:
                    if not isinstance(fp_spec, dict):
                        continue
                    wl_ieee = str(fp_spec.get("ieeeAddr", "") or "")
                    wl_endpoint_specs = fp_spec.get("endpoints") if isinstance(fp_spec.get("endpoints"), list) else None
                    wl_endpoint_idx, wl_endpoint_count = self._append_fingerprint_endpoints(wl_endpoint_specs)

                    wl_flags = 0
                    raw_mfg_code = fp_spec.get("manufacturerID", fp_spec.get("manufacturerCode"))
                    if raw_mfg_code is not None and str(raw_mfg_code).strip() != "":
                        wl_flags |= FINGERPRINT_FLAG_MANUFACTURER_CODE
                    if wl_ieee:
                        wl_flags |= FINGERPRINT_FLAG_IEEE_ADDR
                    if wl_endpoint_specs is not None:
                        wl_flags |= FINGERPRINT_FLAG_ENDPOINTS
                    wl = struct.pack(
                        "<IIIIIIIIIIIHhBBBhhhhB4s",
                        fnv1a_32(f"{str(fp_spec.get('manufacturerName', '') or '')}|{str(fp_spec.get('modelID', '') or '')}"),
                        rec_start,
                        self.add_string(str(white_label.get("model", "") or "")),
                        self.add_string(str(white_label.get("vendor", "") or "")),
                        self.add_string(str(white_label.get("description", "") or "")),
                        self.add_string(str(fp_spec.get("manufacturerName", "") or "")),
                        self.add_string(str(fp_spec.get("modelID", "") or "")),
                        self.add_string(wl_ieee),
                        self.add_string(str(fp_spec.get("dateCode", "") or "")),
                        self.add_string(str(fp_spec.get("softwareBuildID", "") or "")),
                        wl_endpoint_idx,
                        to_int(raw_mfg_code, 0) & 0xFFFF,
                        to_int(fp_spec.get("priority", 0)),
                        {"Router": 1, "EndDevice": 2}.get(str(fp_spec.get("type", "") or ""), 0),
                        {"Unknown": 0xFF, "Mains (single phase)": 1, "Mains (3 phase)": 2,
                         "Battery": 3, "DC Source": 4, "Emergency mains constantly powered": 5,
                         "Emergency mains and transfer switch": 6}.get(str(fp_spec.get("powerSource", "") or ""), 0xFF),
                        wl_flags,
                        optional_int(fp_spec.get("applicationVersion")),
                        optional_int(fp_spec.get("hardwareVersion")),
                        optional_int(fp_spec.get("stackVersion")),
                        optional_int(fp_spec.get("zclVersion")),
                        wl_endpoint_count,
                        b"\x00" * 4
                    )
                    assert len(wl) == WHITE_LABEL_SIZE, len(wl)
                    self.white_label_entries.append(wl)

            # Keep the record span in sync with the complete on-wire layout.
            # Reporting entries are 8 bytes (cluster/attr/min/max), so this
            # must be computed only after every tail block is written.
            rec_len = len(data_buffer) - rec_start
            record_map.append((rec_start, rec_len))

            # Generate model index entries. Duplicate model keys are retained
            # and marked ambiguous; firmware must not choose one arbitrarily.
            for m in self._model_keys(dev):
                m_hash = fnv1a_32(m)
                v_hash = fnv1a_32(vendor)
                entry_flags = flags & 0xFFFF
                if m_hash in ambiguous_model_hashes:
                    entry_flags |= FLAG_AMBIGUOUS_MODEL
                exact_model_keys = self._flag_model_keys(dev, "exactModels")
                normalized_model_keys = self._flag_model_keys(dev, "normalizedModels")
                fallback_model_keys = self._fallback_model_keys(dev)
                normalized_m = _normalize_model_key(m)
                if any(_normalize_model_key(k) == normalized_m for k in fallback_model_keys):
                    entry_flags |= FLAG_MODEL_FALLBACK
                if m in exact_model_keys:
                    entry_flags |= FLAG_MODEL_EXACT_KEY
                if m in normalized_model_keys:
                    entry_flags |= FLAG_MODEL_NORMALIZED_KEY
                if dev.get("hasZigbeeModel") is True:
                    entry_flags |= FLAG_HAS_ZIGBEE_MODEL

                # ZHC resolves model-only fallback in MODELS_INDEX order.
                # Store that candidate rank in extra so the runtime can keep
                # the same first-match behavior without RAM tables.
                model_rank = self._model_priority(dev, m)

                entry = struct.pack(
                    "<IIIIHHBBBBQ",
                    m_hash,
                    v_hash,
                    rec_start,
                    rec_len,
                    cat_enum,
                    entry_flags,
                    min(len(fz_rules), 255),
                    min(len(tz_rules), 255),
                    min(len(tuya_dps), 255),
                    min(len(endpoints), 255),
                    model_rank
                )
                self.model_index_entries.append((m_hash, entry))

            # Generate fingerprint index entries. Duplicate fingerprint keys
            # are retained and marked ambiguous for deterministic firmware
            # resolution based on rule completeness.
            # Each distinct constraint gets its own index entry and v5
            # constraint record. Never collapse variants of the same
            # manufacturerName|modelID pair.
            for fp in self._fingerprint_constraints(dev):
                fp_key = fp["key"]
                fp_mfg = fp_key.split("|", 1)[0]
                fp_hash = fnv1a_32(fp_key)
                v_hash = fnv1a_32(fp_mfg)
                entry_flags = flags & 0xFFFF
                if fp_hash in ambiguous_fingerprint_hashes:
                    entry_flags |= FLAG_AMBIGUOUS_FINGERPRINT

                # v5 IndexEntry.extra stores the constraint-table index.
                constraint_idx = len(self.fingerprint_constraints)
                ieee = fp["ieee_addr"]
                endpoint_specs = fp["endpoints"]
                endpoint_idx, endpoint_count = self._append_fingerprint_endpoints(endpoint_specs)

                constraint_flags = 0
                if fp["manufacturer_code_defined"]:
                    constraint_flags |= FINGERPRINT_FLAG_MANUFACTURER_CODE
                if ieee:
                    constraint_flags |= FINGERPRINT_FLAG_IEEE_ADDR
                if endpoint_specs is not None:
                    constraint_flags |= FINGERPRINT_FLAG_ENDPOINTS
                constraint = struct.pack(
                    "<IIIIIHhBBBhhhhhIIB2sII",
                    fp_hash,
                    rec_start,
                    self.add_string(fp["date_code"]),
                    self.add_string(fp["software_build_id"]),
                    fp["source_order"],
                    fp["manufacturer_code"],
                    fp["priority"],
                    {"Router": 1, "EndDevice": 2}.get(fp["type"], 0),
                    {"Unknown": 0xFF, "Mains (single phase)": 1, "Mains (3 phase)": 2,
                     "Battery": 3, "DC Source": 4, "Emergency mains constantly powered": 5,
                     "Emergency mains and transfer switch": 6}.get(fp["power_source"], 0xFF),
                    constraint_flags,
                    fp["application_version"],
                    fp["hardware_version"],
                    fp["stack_version"],
                    fp["zcl_version"],
                    fp["model_priority"],
                    self.add_string(ieee),
                    endpoint_idx,
                    endpoint_count,
                    b"\x00" * 2,
                    self.add_string(fp["manufacturer_name"]),
                    self.add_string(fp["model_id"])
                )
                assert len(constraint) == FINGERPRINT_CONSTRAINT_SIZE
                self.fingerprint_constraints.append(constraint)

                fp_entry = struct.pack(
                    "<IIIIHHBBBBQ",
                    fp_hash,
                    v_hash,
                    rec_start,
                    rec_len,
                    cat_enum,
                    entry_flags,
                    min(len(fz_rules), 255),
                    min(len(tz_rules), 255),
                    min(len(tuya_dps), 255),
                    min(len(endpoints), 255),
                    constraint_idx
                )
                self.fp_index_entries.append((fp_hash, fp_entry))

        # Sort indexes strictly by hash ascending for binary search.
        self.model_index_entries.sort(key=lambda x: x[0])
        self.fp_index_entries.sort(key=lambda x: x[0])

        model_idx_bytes = b"".join(e[1] for e in self.model_index_entries)
        fp_idx_bytes = b"".join(e[1] for e in self.fp_index_entries)
        endpoint_bytes = b"".join(self.fingerprint_endpoints)
        cluster_bytes = b"".join(struct.pack("<H", c) for c in self.fingerprint_clusters)
        constraint_bytes = b"".join(self.fingerprint_constraints)
        white_label_bytes = b"".join(self.white_label_entries)

        model_idx_off = HEADER_SIZE
        fp_idx_off = model_idx_off + len(model_idx_bytes)
        endpoint_off = fp_idx_off + len(fp_idx_bytes)
        cluster_off = endpoint_off + len(endpoint_bytes)
        white_label_off = cluster_off + len(cluster_bytes)
        constraints_off = white_label_off + len(white_label_bytes)
        records_off = constraints_off + len(constraint_bytes)
        record_data_size = len(data_buffer)
        vm_code_bytes = b"".join(self.vm_programs)
        vm_code_off = records_off + record_data_size
        strings_off = vm_code_off + len(vm_code_bytes)
        total_size = strings_off + len(self.string_table)

        payload = (model_idx_bytes + fp_idx_bytes + endpoint_bytes + cluster_bytes +
                   white_label_bytes + constraint_bytes + data_buffer + vm_code_bytes + self.string_table)
        sha256_raw = hashlib.sha256(payload).digest()
        crc_val = 0  # Optional CRC

        reserved = struct.pack(
            "<IIIIII",
            endpoint_off,
            len(self.fingerprint_endpoints),
            cluster_off,
            len(self.fingerprint_clusters),
            white_label_off,
            len(self.white_label_entries),
        ) + struct.pack(
            "<IIHHII",
            vm_code_off,
            len(vm_code_bytes),
            VM_VERSION,
            required_capabilities & 0xFFFF,
            record_data_size,
            len(self.vm_programs),
        )
        header = struct.pack(
            "<4sHHIIIIIIIII32sII44s",
            MAGIC,
            FORMAT_VERSION,
            IR_VERSION,
            len(self.records),
            model_idx_off,
            len(self.model_index_entries),
            fp_idx_off,
            len(self.fp_index_entries),
            records_off,
            strings_off,
            total_size,
            crc_val,
            sha256_raw,
            constraints_off,
            len(self.fingerprint_constraints),
            reserved
        )
        assert len(header) == HEADER_SIZE, len(header)

        full_binary = header + payload

        with open(out_bin_path, "wb") as f:
            f.write(full_binary)

        sha256_hex = hashlib.sha256(full_binary).hexdigest()
        print(f"[Binary Compiler v10] Successfully compiled Binary Bundle: {out_bin_path}")
        print(f"  - Device Records: {len(self.records)}")
        print(f"  - Model Index Entries: {len(self.model_index_entries)} ({len(model_idx_bytes)} bytes)")
        print(f"  - Fingerprint Index Entries: {len(self.fp_index_entries)} ({len(fp_idx_bytes)} bytes)")
        print(f"  - Fingerprint Constraints: {len(self.fingerprint_constraints)} ({len(constraint_bytes)} bytes)")
        print(f"  - Fingerprint Endpoints: {len(self.fingerprint_endpoints)} ({len(endpoint_bytes)} bytes)")
        print(f"  - Fingerprint Clusters: {len(self.fingerprint_clusters)} ({len(cluster_bytes)} bytes)")
        print(f"  - White-label Entries: {len(self.white_label_entries)} ({len(white_label_bytes)} bytes)")
        print(f"  - Ambiguous Model Keys: {stats['ambiguous_model_count']}")
        print(f"  - Duplicate Fingerprint Keys: {stats['duplicate_fingerprint_count']}")
        print(f"  - Model Hash Collisions: {stats['model_hash_collision_count']}")
        print(f"  - Fingerprint Hash Collisions: {stats['fingerprint_hash_collision_count']}")
        print(f"  - Record Data Buffer: {len(data_buffer)} bytes")
        print(f"  - VM Programs: {len(self.vm_programs)} ({len(vm_code_bytes)} bytes)")
        print(f"  - String Table: {len(self.string_table)} bytes")
        print(f"  - Total Binary Size: {len(full_binary)} bytes ({len(full_binary) / 1024 / 1024:.2f} MB)")
        print(f"  - SHA256: {sha256_hex}")

        return {
            "format": "z2m-binary-bundle-v10",
            "version": "10.0.0",
            "ir_version": IR_VERSION,
            "bundle": os.path.basename(out_bin_path),
            "bytes": len(full_binary),
            "sha256": sha256_hex,
            "device_count": len(self.records),
            "model_index_count": len(self.model_index_entries),
            "fingerprint_index_count": len(self.fp_index_entries),
            "fingerprint_constraint_count": len(self.fingerprint_constraints),
            "index_entry_size": INDEX_ENTRY_SIZE,
            "ambiguous_model_count": stats["ambiguous_model_count"],
            "duplicate_fingerprint_count": stats["duplicate_fingerprint_count"],
            "model_hash_collision_count": stats["model_hash_collision_count"],
            "fingerprint_hash_collision_count": stats["fingerprint_hash_collision_count"],
            "vm_program_count": len(self.vm_programs),
            "vm_code_size": len(vm_code_bytes),
            "required_capability_mask": required_capabilities,
        }


def compile_bundle(input_dir: str, out_bin: str, out_manifest: str):
    builder = BinaryBundleBuilderV4()
    bundle_ndjson = os.path.join(input_dir, "z2m_bundle.ndjson")
    if not os.path.exists(bundle_ndjson):
        bundle_ndjson = os.path.join(input_dir, "z2m_bundle.json")

    assert os.path.exists(bundle_ndjson), f"Bundle NDJSON file not found at {bundle_ndjson}!"

    print(f"[Binary Compiler v10] Reading IR records from {bundle_ndjson}...")
    if bundle_ndjson.endswith(".json"):
        with open(bundle_ndjson, "r", encoding="utf-8") as f:
            parsed = json.load(f)
        records = parsed if isinstance(parsed, list) else parsed.get("devices", [])
        if not isinstance(records, list):
            raise ValueError(f"JSON bundle {bundle_ndjson} does not contain a record list")
        for rec in records:
            if not isinstance(rec, dict):
                raise ValueError(f"Invalid record in {bundle_ndjson}: expected object")
            builder.add_record(rec)
    else:
        with open(bundle_ndjson, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON in {bundle_ndjson} at line {line_no}: {exc}") from exc
                if not isinstance(rec, dict):
                    raise ValueError(f"Invalid record in {bundle_ndjson} at line {line_no}: expected object")
                builder.add_record(rec)

    os.makedirs(os.path.dirname(out_bin) or ".", exist_ok=True)
    meta = builder.build(out_bin)

    manifest_data = {
        "format": "z2m-binary-bundle-v10",
        "bundle_version": "10.0.0",
        "ir_version": IR_VERSION,
        "min_firmware": "v10.0.0",
        "bundle": os.path.basename(out_bin),
        "bytes": meta["bytes"],
        "sha256": meta["sha256"],
        "device_count": meta["device_count"],
        "model_index_count": meta["model_index_count"],
        "fingerprint_index_count": meta["fingerprint_index_count"],
        "fingerprint_constraint_count": meta["fingerprint_constraint_count"],
        "ambiguous_model_count": meta["ambiguous_model_count"],
        "duplicate_fingerprint_count": meta["duplicate_fingerprint_count"],
        "model_hash_collision_count": meta["model_hash_collision_count"],
        "fingerprint_hash_collision_count": meta["fingerprint_hash_collision_count"],
        "index_entry_size": INDEX_ENTRY_SIZE,
        "search_algorithm": "binary_search_fnv1a_32",
        "capability_summary": {
            "declarative_inbound": True,
            "declarative_outbound": True,
            "fingerprint_resolution": True,
            "white_label_resolution": True,
            "runtime": "esp32-declarative-ir",
        },
    }

    with open(out_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
    print(f"[Binary Compiler v10] Manifest written to {out_manifest}")


if __name__ == "__main__":
    input_dir = sys.argv[1] if len(sys.argv) > 1 else "build_ir"
    out_bin = sys.argv[2] if len(sys.argv) > 2 else "dist/z2m_bundle.bin"
    out_manifest = sys.argv[3] if len(sys.argv) > 3 else "dist/z2m_manifest.json"
    compile_bundle(input_dir, out_bin, out_manifest)
