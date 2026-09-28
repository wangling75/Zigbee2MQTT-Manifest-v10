#pragma once

#include <stdint.h>
#include <stddef.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>

namespace z2m {

#pragma pack(push, 1)

constexpr uint32_t BUNDLE_MAGIC = 0x424D325A; // 'Z2MB' in little-endian
constexpr uint16_t FORMAT_VERSION = 10;
constexpr uint16_t IR_VERSION = 10;
constexpr uint16_t LEGACY_V9_FORMAT_VERSION = 9;
constexpr uint16_t LEGACY_V9_IR_VERSION = 9;
constexpr uint16_t LEGACY_V8_FORMAT_VERSION = 8;
constexpr uint16_t LEGACY_V8_IR_VERSION = 8;
constexpr uint16_t LEGACY_V7_FORMAT_VERSION = 7;
constexpr uint16_t LEGACY_V7_IR_VERSION = 7;
constexpr uint16_t LEGACY_V6_FORMAT_VERSION = 6;
constexpr uint16_t LEGACY_V6_IR_VERSION = 6;
constexpr uint16_t LEGACY_V5_FORMAT_VERSION = 5;
constexpr uint16_t LEGACY_V5_IR_VERSION = 5;
constexpr uint16_t LEGACY_V4_FORMAT_VERSION = 4;
constexpr uint16_t LEGACY_V4_IR_VERSION = 4;
constexpr uint16_t LEGACY_FORMAT_VERSION = 3;
constexpr uint16_t LEGACY_IR_VERSION = 3;
constexpr size_t HEADER_SIZE = 128;
constexpr size_t INDEX_ENTRY_SIZE = 32;
// v7+ appends the exact-case manufacturerName/modelID string offsets.
constexpr size_t FINGERPRINT_CONSTRAINT_SIZE = 56;
// v5/v6 use the common prefix without the two trailing offsets.
constexpr size_t LEGACY_V6_CONSTRAINT_SIZE = 48;
constexpr size_t FINGERPRINT_ENDPOINT_SIZE = 16;
constexpr size_t RECORD_V9_EXTENSION_SIZE = 20;
constexpr size_t RECORD_V10_BATTERY_EXTENSION_SIZE = 32;
constexpr size_t VM_INSTRUCTION_SIZE = 12;
constexpr uint16_t VM_VERSION = 1;
constexpr uint32_t VM_CAPABILITY_BASE = 0x00000001;
constexpr uint32_t VM_CAPABILITY_TUYA = 0x00000002;
constexpr uint32_t VM_CAPABILITY_ZCL_WRITE = 0x00000004;
constexpr uint32_t VM_CAPABILITY_IGNORE = 0x00000008;
constexpr uint32_t VM_CAPABILITY_STATIC_IGNORE = 0x00000010;
constexpr uint32_t VM_CAPABILITY_TUYA_FIRST_DP = 0x00000020;
constexpr uint32_t VM_CAPABILITY_TUYA_COMPOSITE_OMIT = 0x00000040;
constexpr uint32_t VM_CAPABILITY_COMMAND_EVENT = 0x00000080;
constexpr uint32_t VM_CAPABILITY_BATTERY_SEMANTICS = 0x00000100;
constexpr uint32_t VM_CAPABILITY_IAS_SEMANTICS = 0x00000200;
constexpr uint32_t VM_PROGRAM_ABSENT = 0xFFFFFFFFu;
constexpr uint16_t RECORD_V9_FLAG_MULTI_ENDPOINT = 0x0001;
constexpr uint32_t VM_PROGRAM_MAX_INSTRUCTIONS = 4096;
constexpr uint32_t VM_MAX_STEPS = 8192;
constexpr uint32_t VM_MAX_STACK = 64;
constexpr uint8_t FP_FLAG_MANUFACTURER_CODE = 0x01;
constexpr uint8_t FP_FLAG_IEEE_ADDR = 0x02;
constexpr uint8_t FP_FLAG_ENDPOINTS = 0x04;

// Binary Bundle Header (128 bytes)
struct BundleHeader {
    char magic[4];             // "Z2MB"
    uint16_t version;          // 6
    uint16_t ir_version;       // 6
    uint32_t device_count;     // Total devices
    uint32_t model_idx_offset; // Byte offset of model index
    uint32_t model_idx_count;  // Count of model index entries
    uint32_t fp_idx_offset;    // Byte offset of fingerprint index
    uint32_t fp_idx_count;     // Count of fingerprint index entries
    uint32_t records_offset;   // Byte offset of records buffer
    uint32_t strings_offset;   // Byte offset of string table
    uint32_t total_size;       // Total size of binary file
    uint32_t crc32;            // CRC32 value
    uint8_t sha256[32];        // SHA256 of payload
    uint32_t fp_constraints_offset; // v5+: byte offset of fingerprint constraints
    uint32_t fp_constraints_count;  // v5+: count of fingerprint constraints
    // v7: reserved[24..27] is the declared-zigbeeModel table offset and
    // reserved[28..31] is its byte size. The table carries the exact
    // declared zigbeeModel strings needed by ZHC's final fallback.
    // v9 appends VM metadata at reserved[24..43]. The first 24 bytes
    // retain the v6-v8 endpoint/cluster/white-label table offsets.
    uint8_t reserved[44];      // v6: endpoint/cluster table offset+count words
};

// Fixed 32-byte Index Entry for O(log N) binary search
struct IndexEntry {
    uint32_t hash;             // FNV1a-32 hash of model or mfg|model
    uint32_t sec_hash;         // FNV1a-32 hash of vendor
    uint32_t record_offset;    // Relative offset in records section
    uint32_t record_len;       // Total byte size of record
    uint16_t category;         // Device category enum
    uint16_t flags;            // Flags (bit0: tuya, bit1: battery, bit2: multiep, etc.)
    uint8_t fz_count;          // Number of fromZigbee IR rules
    uint8_t tz_count;          // Number of toZigbee IR rules
    uint8_t dp_count;          // Number of Tuya DP rules
    uint8_t ep_count;          // Number of endpoints
    uint64_t extra;            // v5+: constraint index; v3/v4: manufacturerCode
};

// Fingerprint constraint record (48 bytes, v5+)
struct FingerprintConstraint {
    uint32_t fp_hash;          // FNV1a-32 of manufacturerName|modelID
    uint32_t record_offset;    // Relative offset in records section
    uint32_t date_str_offset;  // 0 = unconstrained
    uint32_t sw_str_offset;    // 0 = unconstrained
    uint32_t source_order;     // Stable upstream fingerprint order
    uint16_t manufacturer_code;// 0 = unconstrained
    int16_t priority;          // ZHC fingerprint priority
    uint8_t type;              // 0=unconstrained, 1=Router, 2=EndDevice
    uint8_t power_source;      // 0xFF=unconstrained, otherwise ZCL enum
    uint8_t flags;             // bit0: manufacturer_code, bit1: IEEE, bit2: endpoints
    int16_t application_version; // -1 = unconstrained
    int16_t hardware_version;    // -1 = unconstrained
    int16_t stack_version;       // -1 = unconstrained
    int16_t zcl_version;         // -1 = unconstrained
    int16_t model_priority;      // MODELS_INDEX candidate rank; 32767 = unknown
    uint32_t ieee_str_offset;    // v6: regex source, 0 = unconstrained
    uint32_t endpoint_offset;    // v6: offset into endpoint constraint table
    uint8_t endpoint_count;      // v6: number of endpoint constraints
    uint8_t reserved[2];
    // v7+: ZHC compares these fields with strict (case-sensitive)
    // equality, so preserve the exact declared strings.
    uint32_t mfg_str_offset;   // 0 = unconstrained
    uint32_t model_str_offset; // 0 = unconstrained
};

// One ZHC fingerprint endpoint constraint (16 bytes, v6 only).
struct FingerprintEndpoint {
    uint16_t input_offset;     // offset into flat uint16 cluster table
    uint16_t input_count;
    uint16_t output_offset;
    uint16_t output_count;
    uint16_t profile_id;       // 0xFFFF = unconstrained
    uint16_t device_id;        // 0xFFFF = unconstrained
    uint8_t id;                // endpoint ID
    uint8_t flags;             // bit0 profile, bit1 device, bit2 input, bit3 output
    uint16_t reserved;         // keep the record 16-byte aligned
};

static_assert(sizeof(BundleHeader) == HEADER_SIZE, "BundleHeader must be 128 bytes");
static_assert(sizeof(IndexEntry) == INDEX_ENTRY_SIZE, "IndexEntry must be 32 bytes");
static_assert(sizeof(FingerprintConstraint) == FINGERPRINT_CONSTRAINT_SIZE, "FingerprintConstraint must be 56 bytes");
static_assert(sizeof(FingerprintEndpoint) == FINGERPRINT_ENDPOINT_SIZE, "FingerprintEndpoint must be 16 bytes");

// One ZHC white-label fingerprint (64 bytes, v6 only). The strings are
// offsets into the shared string table; 0 means the field is unconstrained.
struct WhiteLabelIR {
    uint32_t fp_hash;
    uint32_t record_offset;
    uint32_t model_str_offset;
    uint32_t vendor_str_offset;
    uint32_t desc_str_offset;
    uint32_t fp_mfg_str_offset;
    uint32_t fp_model_str_offset;
    uint32_t ieee_str_offset;
    uint32_t date_str_offset;
    uint32_t sw_str_offset;
    uint32_t endpoint_offset;
    uint16_t manufacturer_code;
    int16_t priority;
    uint8_t type;
    uint8_t power_source;
    uint8_t flags;
    int16_t application_version;
    int16_t hardware_version;
    int16_t stack_version;
    int16_t zcl_version;
    uint8_t endpoint_count;
    uint8_t reserved[4];
};

static_assert(sizeof(WhiteLabelIR) == 64, "WhiteLabelIR must be 64 bytes");

// Device Record Header (20 bytes)
struct RecordHeader {
    uint32_t model_str_offset;
    uint32_t vendor_str_offset;
    uint32_t desc_str_offset;
    uint8_t category;
    uint8_t flags;
    uint8_t fz_count;
    uint8_t tz_count;
    uint8_t dp_count;
    uint8_t ep_count;
    uint8_t bind_count;
    uint8_t reporting_count;
};

// RecordHeader.flags bits 5..7 describe declarative support coverage.
constexpr uint8_t RECORD_FLAG_HAS_INBOUND = 0x20;
constexpr uint8_t RECORD_FLAG_HAS_OUTBOUND = 0x40;
constexpr uint8_t RECORD_FLAG_LIMITED = 0x80;

// v8 record extension, stored immediately after RecordHeader. The model
// list is an array of uint32_t string-table offsets at declared_models_offset
// (relative to the records section). ZHC's final fallback compares these raw
// zigbeeModel declarations with strict equality.
struct RecordV8Extension {
    uint32_t declared_models_offset;
    uint32_t declared_models_count;
};

static_assert(sizeof(RecordV8Extension) == 8, "RecordV8Extension must be 8 bytes");

// v9 record extension, stored immediately after RecordV8Extension. Program
// offsets are relative to the bundle's VM code region. A program is absent
// when its offset is VM_PROGRAM_ABSENT.
struct RecordV9Extension {
    uint32_t from_program_offset;
    uint32_t from_program_size;
    uint32_t to_program_offset;
    uint32_t to_program_size;
    uint16_t vm_version;
    uint16_t flags;
};

static_assert(sizeof(RecordV9Extension) == RECORD_V9_EXTENSION_SIZE,
              "RecordV9Extension must be 20 bytes");

// v10 battery semantics, stored immediately after RecordV9Extension. This
// captures the non-linear and cross-attribute behavior of the official
// fz.battery converter without adding a device-specific branch to firmware.
constexpr uint8_t BATTERY_FLAG_ENABLED = 0x01;
constexpr uint8_t BATTERY_FLAG_PERCENTAGE = 0x02;
constexpr uint8_t BATTERY_FLAG_VOLTAGE = 0x04;
constexpr uint8_t BATTERY_FLAG_LOW_STATUS = 0x08;
constexpr uint8_t BATTERY_FLAG_DONT_DIVIDE_PERCENTAGE = 0x10;
constexpr uint8_t BATTERY_FLAG_TUYA_INVALID_DROP = 0x20;
constexpr uint8_t BATTERY_CURVE_NONE = 0;
constexpr uint8_t BATTERY_CURVE_LINEAR = 1;
constexpr uint8_t BATTERY_CURVE_3V_2100 = 2;
constexpr uint8_t BATTERY_CURVE_3V_1500_2800 = 3;
struct RecordV10BatterySemantics {
    uint8_t flags;
    uint8_t curve;
    uint8_t drop_percentage_value;
    uint8_t drop_voltage_threshold;
    float min_voltage;
    float max_voltage;
    float voltage_offset;
    uint32_t exceptions_str_offset;
    uint8_t reserved[12];
};

static_assert(sizeof(RecordV10BatterySemantics) == RECORD_V10_BATTERY_EXTENSION_SIZE,
              "RecordV10BatterySemantics must be 32 bytes");

// Optional v9 multi-endpoint publish metadata. It is appended after the
// declared-model table only when RECORD_V9_FLAG_MULTI_ENDPOINT is set.
// The skip table contains string-table offsets for multiEndpointSkip values.
struct RecordV9MultiEndpoint {
    uint32_t skip_offset;
    uint16_t skip_count;
    uint16_t reserved;
};

static_assert(sizeof(RecordV9MultiEndpoint) == 8,
              "RecordV9MultiEndpoint must be 8 bytes");

// v9 header reserved[24..43] layout, stored little-endian:
//   [24..27] vm_code_offset (absolute; records end)
//   [28..31] vm_code_size
//   [32..33] vm_version
//   [34..35] required_capability_mask (low 16 bits)
//   [36..39] record_data_size
//   [40..43] vm_program_count
constexpr size_t HEADER_V9_VM_CODE_OFFSET = 24;
constexpr size_t HEADER_V9_VM_CODE_SIZE = 28;
constexpr size_t HEADER_V9_VM_VERSION = 32;
constexpr size_t HEADER_V9_REQUIRED_CAPABILITIES = 34;
constexpr size_t HEADER_V9_RECORD_DATA_SIZE = 36;
constexpr size_t HEADER_V9_VM_PROGRAM_COUNT = 40;

// Endpoint Descriptor (4 bytes)
struct EndpointDesc {
    uint8_t ep_id;
    uint8_t pad8;
    uint16_t name_str_offset;
};

// fromZigbee IR Rule (20 bytes)
struct FromZigbeeIR {
    uint8_t op;                // Opcode: READ_ATTR, REPORT_ATTR, TRANSFORM, MAP_ENUM
    uint8_t datatype;          // Datatype enum
    uint16_t cluster_id;       // Cluster ID (e.g. 0x0402)
    uint16_t attr_id;          // Attribute ID (e.g. 0x0000)
    uint8_t endpoint_id;       // 0 = dynamic / default, >0 = explicit
    uint8_t pad8;
    uint32_t target_str_offset;// Property name string offset
    float scale;               // Multiplier
    float offset;              // Additive offset
};

// v3 toZigbee IR Rule (16 bytes). Kept for backward-compatible decoding.
struct ToZigbeeIRV3 {
    uint8_t op;
    uint8_t endpoint_id;
    uint16_t cluster_id;
    uint16_t cmd_or_attr;
    uint8_t cmd_on;
    uint8_t cmd_off;
    uint32_t target_str_offset;
    float scale;
};

// v4+ toZigbee IR Rule (20 bytes). The datatype byte keeps ZCL writes
// type-correct instead of assuming every attribute is int16.
struct ToZigbeeIR {
    uint8_t op;
    uint8_t endpoint_id;
    uint16_t cluster_id;
    uint16_t cmd_or_attr;
    uint8_t cmd_on;
    uint8_t cmd_off;
    uint32_t target_str_offset;
    float scale;
    uint8_t datatype;          // ZCL datatype for WRITE_ATTR (e.g. 0x30 enum8)
    uint8_t reserved[3];
};

// Tuya DP Rule (20 bytes)
struct TuyaDpIR {
    uint8_t dp_id;             // Tuya Datapoint ID
    uint8_t datatype;          // 0: value, 1: enum, 2: bool, 3: raw, 4: string
    uint8_t send_command;      // 0x00 dataRequest (default), 0x04 sendData
    uint8_t endpoint_id;       // 0 = default endpoint, >0 = explicit endpoint
    uint32_t target_str_offset;// Property name string offset
    float scale;               // Multiplier
    float offset;              // Additive offset
    uint32_t map_str_offset;   // Offset to enum map JSON string if applicable
};

// Tuya DP command encoding. ZHC defaults to dataRequest (0x00); only
// devices whose metadata sets tuyaSendCommand=sendData require 0x04.
constexpr uint8_t TUYA_SEND_COMMAND_DATA_REQUEST = 0x00;
constexpr uint8_t TUYA_SEND_COMMAND_SEND_DATA = 0x04;

static_assert(sizeof(TuyaDpIR) == 20, "TuyaDpIR must be 20 bytes");

// Reporting Configuration (8 bytes)
struct ReportingConfig {
    uint16_t cluster_id;
    uint16_t attr_id;
    uint16_t min_interval;
    uint16_t max_interval;
};

static_assert(sizeof(ReportingConfig) == 8,
              "ReportingConfig must match the v10 8-byte wire layout");

#pragma pack(pop)

// Opcodes
// Restricted VM opcodes. A v9/v10 bundle may only use instructions in this
// table; unsupported capabilities are rejected at load time.
enum class VmOpcode : uint16_t {
    HALT = 0x0000,
    PUSH_CONST = 0x0001,
    LOAD_ZCL = 0x0002,
    LOAD_TUYA = 0x0003,
    PUSH_STRING = 0x0004,
    MATCH_ZCL = 0x0005,
    MATCH_TUYA = 0x0006,
    LOAD_PROPERTY = 0x0007,
    LOAD_PROPERTY_NAME = 0x0008,
    LOAD_ENDPOINT = 0x0009,
    PUSH_BYTES = 0x000A,
    PUSH_FLOAT_BITS = 0x000B,
    TEST_ZCL = 0x000C,
    TEST_TUYA = 0x000D,
    ADD = 0x0010,
    SUB = 0x0011,
    MUL = 0x0012,
    DIV = 0x0013,
    MOD = 0x0014,
    EQ = 0x0020,
    NE = 0x0021,
    LT = 0x0022,
    LE = 0x0023,
    GT = 0x0024,
    GE = 0x0025,
    AND = 0x0026,
    OR = 0x0027,
    NOT = 0x0028,
    BIT_GET = 0x0030,
    BIT_EXTRACT = 0x0031,
    MAP_LOOKUP = 0x0032,
    TO_BOOL = 0x0033,
    TO_STRING = 0x0034,
    JMP = 0x0040,
    JMP_IF_FALSE = 0x0041,
    JMP_IF_TRUE = 0x0042,
    ROUTE_ENDPOINT = 0x0050,
    PUBLISH = 0x0060,
    ZCL_READ = 0x0070,
    ZCL_WRITE = 0x0071,
    ZCL_COMMAND = 0x0072,
    TUYA_READ = 0x0080,
    TUYA_WRITE = 0x0081,
    IGNORE = 0x0090,
    UNSUPPORTED = 0xFFFF
};

// One fixed-width VM instruction. Reserved bits must be zero; the loader
// uses that property to reject malformed or future instructions safely.
struct VmInstruction {
    uint16_t opcode;
    uint16_t flags;
    uint32_t a;
    uint32_t b;
};

static_assert(sizeof(VmInstruction) == VM_INSTRUCTION_SIZE,
              "VmInstruction must be 12 bytes");

enum class Opcode : uint8_t {
    READ_ATTR = 0x01,
    WRITE_ATTR = 0x02,
    COMMAND = 0x03,
    REPORT_ATTR = 0x04,
    BIND_CLUSTER = 0x05,
    TUYA_DP = 0x06,
    TRANSFORM = 0x07,
    MAP_ENUM = 0x08,
    BITFIELD = 0x09,
    DYNAMIC_ENDPOINT = 0x0A,
    IGNORE = 0x0B
};

// Datatypes
enum class DataType : uint8_t {
    BOOL = 0,
    UINT8 = 1,
    INT16 = 2,
    UINT16 = 3,
    INT32 = 4,
    UINT32 = 5,
    ENUM8 = 6,
    RAW = 7,
    STRING = 8,
    SINGLE_PREC = 9,
    DOUBLE_PREC = 10,
    UINT48 = 11,
    INT24 = 12,
    BITMAP16 = 13,
    VALUE = 14
};

// Categories
enum class DeviceCategory : uint8_t {
    GENERIC = 0,
    ON_OFF_LIGHT = 1,
    DIMMABLE_LIGHT = 2,
    COLOR_LIGHT = 3,
    ON_OFF_PLUGIN_UNIT = 4,
    ON_OFF_SWITCH = 5,
    TEMP_SENSOR = 6,
    HUMIDITY_SENSOR = 7,
    CONTACT_SENSOR = 8,
    OCCUPANCY_SENSOR = 9,
    LIGHT_SENSOR = 10,
    WATER_LEAK_SENSOR = 11,
    SMOKE_SENSOR = 12,
    THERMOSTAT = 13,
    WINDOW_COVERING = 14,
    DOOR_LOCK = 15,
    CARBON_MONOXIDE_SENSOR = 16,
    GAS_SENSOR = 17,
    VIBRATION_SENSOR = 18
};

// Flags
constexpr uint16_t FLAG_TUYA = 0x0001;
constexpr uint16_t FLAG_BATTERY = 0x0002;
constexpr uint16_t FLAG_MULTI_EP = 0x0004;
constexpr uint16_t FLAG_COLOR = 0x0008;
constexpr uint16_t FLAG_REPORTING = 0x0010;
constexpr uint16_t FLAG_AMBIGUOUS_MODEL = 0x0020;
constexpr uint16_t FLAG_AMBIGUOUS_FINGERPRINT = 0x0040;
constexpr uint16_t FLAG_MODEL_FALLBACK = 0x0080;
constexpr uint16_t FLAG_MODEL_EXACT_KEY = 0x0100;
constexpr uint16_t FLAG_MODEL_NORMALIZED_KEY = 0x0200;
constexpr uint16_t FLAG_HAS_ZIGBEE_MODEL = 0x0400;

// Property value
struct PropertyValue {
    enum Type { TYPE_NONE, TYPE_BOOL, TYPE_INT, TYPE_FLOAT, TYPE_STRING };
    Type type = TYPE_NONE;
    bool bool_val = false;
    int64_t int_val = 0;
    double float_val = 0.0;
    std::string str_val;

    std::string toString() const {
        if (type == TYPE_BOOL) return bool_val ? "true" : "false";
        if (type == TYPE_INT) return std::to_string(int_val);
        if (type == TYPE_FLOAT) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%.2f", float_val);
            return std::string(buf);
        }
        if (type == TYPE_STRING) return str_val;
        return "";
    }
};

// Device Interview Info
struct EndpointInfo {
    uint8_t ep_id = 1;
    uint16_t profile_id = 0;
    uint16_t device_id = 0;
    std::vector<uint16_t> input_clusters;
    std::vector<uint16_t> output_clusters;
};

struct DeviceInterview {
    uint64_t ieee_addr = 0;
    uint16_t short_addr = 0;
    std::string manufacturer_name;
    std::string model_id;
    uint16_t manufacturer_code = 0;
    std::string date_code;
    std::string software_build_id;
    uint8_t power_source = 0xFF;
    uint8_t logical_type = 0;
    int16_t application_version = -1;
    int16_t hardware_version = -1;
    int16_t stack_version = -1;
    int16_t zcl_version = -1;
    std::vector<EndpointInfo> endpoints;

    bool hasInputCluster(uint16_t cl) const {
        for (const auto& ep : endpoints) {
            for (uint16_t c : ep.input_clusters) if (c == cl) return true;
        }
        return false;
    }

    uint8_t findEndpointForCluster(uint16_t cl) const {
        for (const auto& ep : endpoints) {
            for (uint16_t c : ep.input_clusters) if (c == cl) return ep.ep_id;
        }
        return 0;
    }
};

// ZCL Incoming Attribute Report
struct ZclAttributeReport {
    uint8_t endpoint = 1;
    uint16_t cluster_id = 0;
    uint16_t attribute_id = 0;
    uint8_t datatype = 0;
    const uint8_t* raw_data = nullptr;
    size_t raw_len = 0;
};

// Tuya DP Incoming Frame
struct TuyaDpMessage {
    uint8_t endpoint = 1;
    uint8_t dp_id = 0;
    uint8_t dp_type = 0; // 0: raw, 1: bool, 2: value (4B), 3: string, 4: enum (1B), 5: bitmap
    uint32_t value = 0;
    std::string str_value;
    std::vector<uint8_t> raw_bytes;
};

// Outgoing Zigbee Command
struct ZigbeeCommand {
    uint8_t endpoint = 1;
    uint16_t cluster_id = 0;
    uint8_t command_id = 0;
    bool is_write_attr = false;
    uint16_t attribute_id = 0;
    uint8_t attribute_datatype = 0;
    std::vector<uint8_t> payload;
};

// Fast FNV1a-32 hash
inline uint32_t hash_fnv1a(const std::string& str) {
    uint32_t h = 0x811C9DC5;
    for (char c : str) {
        // Lowercase
        if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
        h ^= static_cast<uint8_t>(c);
        h = (h * 0x01000193);
    }
    return h;
}

} // namespace z2m
