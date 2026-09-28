#include "converter_bundle.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

namespace z2m {

namespace {

uint16_t readLe16(const uint8_t* data) {
    return static_cast<uint16_t>(data[0]) |
           (static_cast<uint16_t>(data[1]) << 8);
}

uint32_t readLe32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

bool isKnownVmOpcode(uint16_t opcode) {
    switch (static_cast<VmOpcode>(opcode)) {
        case VmOpcode::HALT:
        case VmOpcode::PUSH_CONST:
        case VmOpcode::LOAD_ZCL:
        case VmOpcode::LOAD_TUYA:
        case VmOpcode::PUSH_STRING:
        case VmOpcode::MATCH_ZCL:
        case VmOpcode::MATCH_TUYA:
        case VmOpcode::LOAD_PROPERTY:
        case VmOpcode::LOAD_PROPERTY_NAME:
        case VmOpcode::LOAD_ENDPOINT:
        case VmOpcode::PUSH_BYTES:
        case VmOpcode::PUSH_FLOAT_BITS:
        case VmOpcode::TEST_ZCL:
        case VmOpcode::TEST_TUYA:
        case VmOpcode::ADD:
        case VmOpcode::SUB:
        case VmOpcode::MUL:
        case VmOpcode::DIV:
        case VmOpcode::MOD:
        case VmOpcode::EQ:
        case VmOpcode::NE:
        case VmOpcode::LT:
        case VmOpcode::LE:
        case VmOpcode::GT:
        case VmOpcode::GE:
        case VmOpcode::AND:
        case VmOpcode::OR:
        case VmOpcode::NOT:
        case VmOpcode::BIT_GET:
        case VmOpcode::BIT_EXTRACT:
        case VmOpcode::MAP_LOOKUP:
        case VmOpcode::TO_BOOL:
        case VmOpcode::TO_STRING:
        case VmOpcode::JMP:
        case VmOpcode::JMP_IF_FALSE:
        case VmOpcode::JMP_IF_TRUE:
        case VmOpcode::ROUTE_ENDPOINT:
        case VmOpcode::PUBLISH:
        case VmOpcode::ZCL_READ:
        case VmOpcode::ZCL_WRITE:
        case VmOpcode::ZCL_COMMAND:
        case VmOpcode::TUYA_READ:
        case VmOpcode::TUYA_WRITE:
        case VmOpcode::IGNORE:
            return true;
        default:
            return false;
    }
}

// Structural validation only. Opcode-specific operand semantics are checked
// by the VM before execution so this loader does not reject a future, still
// structurally valid program merely because its constant layout differs.
bool validateVmInstruction(const VmInstruction& instruction, uint32_t instruction_count) {
    if (instruction.flags != 0 || !isKnownVmOpcode(instruction.opcode)) return false;
    switch (static_cast<VmOpcode>(instruction.opcode)) {
        case VmOpcode::JMP:
        case VmOpcode::JMP_IF_FALSE:
        case VmOpcode::JMP_IF_TRUE:
            return instruction.a < instruction_count;
        default:
            return true;
    }
}

} // namespace

FileBundleReader::FileBundleReader(const std::string& path) {
    file_ = std::fopen(path.c_str(), "rb");
    if (file_) {
        std::fseek(file_, 0, SEEK_END);
        size_ = std::ftell(file_);
        std::fseek(file_, 0, SEEK_SET);
    }
}

FileBundleReader::~FileBundleReader() {
    if (file_) {
        std::fclose(file_);
        file_ = nullptr;
    }
}

bool FileBundleReader::read(size_t offset, void* dest, size_t size) {
    if (!file_ || !dest || offset > size_ || size > size_ - offset) return false;
    if (std::fseek(file_, static_cast<long>(offset), SEEK_SET) != 0) return false;
    return std::fread(dest, 1, size, file_) == size;
}

bool ConverterBundle::load(std::shared_ptr<IBundleReader> reader) {
    valid_ = false;
    reader_ = reader;
    vm_code_offset_ = 0;
    vm_code_size_ = 0;
    record_data_size_ = 0;
    vm_program_count_ = 0;
    required_capabilities_ = 0;
    if (!reader_ || reader_->size() < HEADER_SIZE) return false;
    if (!reader_->read(0, &header_, sizeof(header_))) return false;
    if (std::memcmp(header_.magic, "Z2MB", 4) != 0) return false;

    const bool is_v10 = (header_.version == FORMAT_VERSION &&
                        header_.ir_version == IR_VERSION);
    const bool is_v9 = (header_.version == LEGACY_V9_FORMAT_VERSION &&
                       header_.ir_version == LEGACY_V9_IR_VERSION);
    const bool is_v8 = (header_.version == LEGACY_V8_FORMAT_VERSION &&
                        header_.ir_version == LEGACY_V8_IR_VERSION);
    const bool is_v7 = (header_.version == LEGACY_V7_FORMAT_VERSION &&
                        header_.ir_version == LEGACY_V7_IR_VERSION);
    const bool is_v6 = (header_.version == LEGACY_V6_FORMAT_VERSION &&
                        header_.ir_version == LEGACY_V6_IR_VERSION);
    const bool is_v5 = (header_.version == LEGACY_V5_FORMAT_VERSION &&
                        header_.ir_version == LEGACY_V5_IR_VERSION);
    const bool is_v4 = (header_.version == LEGACY_V4_FORMAT_VERSION &&
                        header_.ir_version == LEGACY_V4_IR_VERSION);
    const bool is_v3 = (header_.version == LEGACY_FORMAT_VERSION &&
                        header_.ir_version == LEGACY_IR_VERSION);
    if (!is_v10 && !is_v9 && !is_v8 && !is_v7 && !is_v6 && !is_v5 && !is_v4 && !is_v3) return false;

    const bool has_endpoint_tables = is_v10 || is_v9 || is_v8 || is_v7 || is_v6;
    const size_t constraint_size =
        (is_v10 || is_v9 || is_v8 || is_v7) ? FINGERPRINT_CONSTRAINT_SIZE : LEGACY_V6_CONSTRAINT_SIZE;

    if (header_.total_size > reader_->size() ||
        header_.total_size < HEADER_SIZE ||
        header_.model_idx_offset < HEADER_SIZE ||
        header_.model_idx_offset > header_.fp_idx_offset ||
        header_.fp_idx_offset > (has_endpoint_tables ? header_.fp_constraints_offset
                                                     : header_.records_offset) ||
        header_.records_offset > header_.strings_offset ||
        header_.strings_offset > header_.total_size) {
        return false;
    }

    auto add_would_overflow = [](uint64_t value, uint64_t count, uint64_t stride) -> bool {
        return count != 0 && value > UINT64_MAX - count * stride;
    };
    if (add_would_overflow(header_.model_idx_offset, header_.model_idx_count, INDEX_ENTRY_SIZE) ||
        add_would_overflow(header_.fp_idx_offset, header_.fp_idx_count, INDEX_ENTRY_SIZE)) {
        return false;
    }
    const uint64_t model_idx_end =
        static_cast<uint64_t>(header_.model_idx_offset) +
        static_cast<uint64_t>(header_.model_idx_count) * INDEX_ENTRY_SIZE;
    const uint64_t fp_idx_end =
        static_cast<uint64_t>(header_.fp_idx_offset) +
        static_cast<uint64_t>(header_.fp_idx_count) * INDEX_ENTRY_SIZE;
    if (model_idx_end > header_.fp_idx_offset ||
        fp_idx_end > (has_endpoint_tables ? header_.fp_constraints_offset
                                          : header_.records_offset)) {
        return false;
    }

    if (is_v5 || is_v4 || is_v3) {
        const size_t expected_constraints_offset =
            header_.fp_idx_offset + static_cast<size_t>(header_.fp_idx_count) * INDEX_ENTRY_SIZE;
        const size_t expected_records_offset = is_v5
            ? expected_constraints_offset + static_cast<size_t>(header_.fp_constraints_count) * constraint_size
            : expected_constraints_offset;
        if (is_v5 && (header_.fp_constraints_offset != expected_constraints_offset ||
                      header_.records_offset != expected_records_offset ||
                      header_.fp_constraints_offset > header_.records_offset)) {
            return false;
        }
        if (!is_v5 && header_.records_offset != expected_records_offset) return false;
    } else if (has_endpoint_tables) {
        auto reserved_u32 = [&](size_t off) -> uint32_t {
            return readLe32(&header_.reserved[off]);
        };
        const uint32_t fp_endpoint_offset = reserved_u32(0);
        const uint32_t fp_endpoint_count = reserved_u32(4);
        const uint32_t fp_cluster_offset = reserved_u32(8);
        const uint32_t fp_cluster_count = reserved_u32(12);
        const uint32_t white_label_offset = reserved_u32(16);
        const uint32_t white_label_count = reserved_u32(20);
        const size_t expected_endpoint_offset =
            header_.fp_idx_offset + static_cast<size_t>(header_.fp_idx_count) * INDEX_ENTRY_SIZE;
        const size_t expected_cluster_offset =
            expected_endpoint_offset + static_cast<size_t>(fp_endpoint_count) * FINGERPRINT_ENDPOINT_SIZE;
        const size_t expected_white_label_offset =
            expected_cluster_offset + static_cast<size_t>(fp_cluster_count) * sizeof(uint16_t);
        const size_t expected_constraints_offset =
            expected_white_label_offset + static_cast<size_t>(white_label_count) * sizeof(WhiteLabelIR);
        const size_t expected_records_offset =
            expected_constraints_offset + static_cast<size_t>(header_.fp_constraints_count) * constraint_size;
        if (add_would_overflow(expected_endpoint_offset, fp_endpoint_count, FINGERPRINT_ENDPOINT_SIZE) ||
            add_would_overflow(expected_cluster_offset, fp_cluster_count, sizeof(uint16_t)) ||
            add_would_overflow(expected_white_label_offset, white_label_count, sizeof(WhiteLabelIR)) ||
            add_would_overflow(expected_constraints_offset, header_.fp_constraints_count, constraint_size) ||
            fp_endpoint_offset != expected_endpoint_offset ||
            fp_cluster_offset != expected_cluster_offset ||
            white_label_offset != expected_white_label_offset ||
            header_.fp_constraints_offset != expected_constraints_offset ||
            header_.records_offset != expected_records_offset) {
            return false;
        }
    }

    if (header_.records_offset < HEADER_SIZE ||
        header_.records_offset >= header_.strings_offset) {
        return false;
    }

    if (is_v10 || is_v9) {
        vm_code_offset_ = readLe32(&header_.reserved[HEADER_V9_VM_CODE_OFFSET]);
        vm_code_size_ = readLe32(&header_.reserved[HEADER_V9_VM_CODE_SIZE]);
        const uint16_t vm_version = readLe16(&header_.reserved[HEADER_V9_VM_VERSION]);
        required_capabilities_ = readLe16(&header_.reserved[HEADER_V9_REQUIRED_CAPABILITIES]);
        record_data_size_ = readLe32(&header_.reserved[HEADER_V9_RECORD_DATA_SIZE]);
        vm_program_count_ = readLe32(&header_.reserved[HEADER_V9_VM_PROGRAM_COUNT]);
        const uint16_t supported_caps = static_cast<uint16_t>(
            VM_CAPABILITY_BASE | VM_CAPABILITY_TUYA | VM_CAPABILITY_ZCL_WRITE |
            VM_CAPABILITY_IGNORE | VM_CAPABILITY_STATIC_IGNORE |
            VM_CAPABILITY_TUYA_FIRST_DP | VM_CAPABILITY_TUYA_COMPOSITE_OMIT |
            VM_CAPABILITY_COMMAND_EVENT | VM_CAPABILITY_BATTERY_SEMANTICS |
            VM_CAPABILITY_IAS_SEMANTICS);
        if (vm_version != VM_VERSION || (required_capabilities_ & ~supported_caps) != 0) return false;
        if (record_data_size_ == 0 || vm_program_count_ > 65535) return false;
        if (record_data_size_ > header_.strings_offset - header_.records_offset) return false;
        if (vm_code_offset_ != header_.records_offset + record_data_size_) return false;
        if (vm_code_offset_ > header_.strings_offset ||
            vm_code_size_ != header_.strings_offset - vm_code_offset_ ||
            vm_code_size_ % VM_INSTRUCTION_SIZE != 0) {
            return false;
        }

        // Read the indexes directly: readModelIndexEntry/readFpIndexEntry are
        // deliberately guarded by valid_, which is false during this audit.
        std::vector<uint32_t> record_offsets;
        record_offsets.reserve(header_.model_idx_count + header_.fp_idx_count);
        auto collect_record = [&](const IndexEntry& entry) -> bool {
            if (entry.record_offset > record_data_size_ ||
                entry.record_len > record_data_size_ - entry.record_offset ||
                entry.record_len < sizeof(RecordHeader) + sizeof(RecordV8Extension) + sizeof(RecordV9Extension)) {
                return false;
            }
            const size_t required = sizeof(RecordHeader) + sizeof(RecordV8Extension) +
                                    sizeof(RecordV9Extension) +
                                    (is_v10 ? sizeof(RecordV10BatterySemantics) : 0);
            if (entry.record_len < required) return false;
            record_offsets.push_back(entry.record_offset);
            return true;
        };
        for (uint32_t i = 0; i < header_.model_idx_count; ++i) {
            IndexEntry entry{};
            const size_t off = header_.model_idx_offset + i * INDEX_ENTRY_SIZE;
            if (!reader_->read(off, &entry, sizeof(entry)) || !collect_record(entry)) return false;
        }
        for (uint32_t i = 0; i < header_.fp_idx_count; ++i) {
            IndexEntry entry{};
            const size_t off = header_.fp_idx_offset + i * INDEX_ENTRY_SIZE;
            if (!reader_->read(off, &entry, sizeof(entry)) || !collect_record(entry)) return false;
        }
        std::sort(record_offsets.begin(), record_offsets.end());
        record_offsets.erase(std::unique(record_offsets.begin(), record_offsets.end()), record_offsets.end());
        std::vector<std::pair<uint32_t, uint32_t>> program_ranges;
        uint32_t referenced_programs = 0;
        for (uint32_t record_offset : record_offsets) {
            RecordV9Extension ext{};
            const size_t ext_off = header_.records_offset + record_offset +
                                   sizeof(RecordHeader) + sizeof(RecordV8Extension);
            if (!reader_->read(ext_off, &ext, sizeof(ext)) ||
                ext.vm_version != VM_VERSION ||
                (ext.flags & ~RECORD_V9_FLAG_MULTI_ENDPOINT) != 0) {
                return false;
            }
            auto validate_program = [&](uint32_t offset, uint32_t size) -> bool {
                if (offset == VM_PROGRAM_ABSENT) return size == 0;
                ++referenced_programs;
                if (size == 0 || size % VM_INSTRUCTION_SIZE != 0 ||
                    offset % VM_INSTRUCTION_SIZE != 0 ||
                    offset > vm_code_size_ || size > vm_code_size_ - offset ||
                    size / VM_INSTRUCTION_SIZE > VM_PROGRAM_MAX_INSTRUCTIONS) {
                    return false;
                }
                program_ranges.emplace_back(offset, size);
                const uint32_t count = size / VM_INSTRUCTION_SIZE;
                for (uint32_t index = 0; index < count; ++index) {
                    VmInstruction instruction{};
                    const size_t off = vm_code_offset_ + offset + index * VM_INSTRUCTION_SIZE;
                    if (!reader_->read(off, &instruction, sizeof(instruction)) ||
                        !validateVmInstruction(instruction, count)) {
                        return false;
                    }
                }
                return true;
            };
            if (!validate_program(ext.from_program_offset, ext.from_program_size) ||
                !validate_program(ext.to_program_offset, ext.to_program_size)) {
                return false;
            }
        }
        if (referenced_programs != vm_program_count_) return false;
        std::sort(program_ranges.begin(), program_ranges.end());
        for (size_t i = 1; i < program_ranges.size(); ++i) {
            const uint64_t prev_end = static_cast<uint64_t>(program_ranges[i - 1].first) +
                                      program_ranges[i - 1].second;
            if (prev_end > program_ranges[i].first) return false;
        }
    }

    valid_ = true;
    return true;
}

std::string ConverterBundle::getString(uint32_t offset) const {
    if (!valid_ || !reader_ || offset == 0) return "";
    size_t abs_off = header_.strings_offset + offset;
    if (abs_off >= reader_->size()) return "";

    // v7 stores an explicit little-endian length prefix so values that
    // contain embedded NULs survive. Older formats are NUL-terminated.
    if (header_.version >= LEGACY_V7_FORMAT_VERSION) {
        uint8_t len_bytes[2] = {0, 0};
        if (!reader_->read(abs_off, len_bytes, sizeof(len_bytes))) return "";
        const size_t len = static_cast<size_t>(len_bytes[0]) |
                           (static_cast<size_t>(len_bytes[1]) << 8);
        abs_off += sizeof(len_bytes);
        if (abs_off > reader_->size() || len > reader_->size() - abs_off) return "";
        if (const uint8_t* ptr = reader_->directPointer(abs_off, len)) {
            return std::string(reinterpret_cast<const char*>(ptr), len);
        }
        std::string result(len, '\0');
        if (len > 0 && !reader_->read(abs_off, &result[0], len)) return "";
        return result;
    }

    // Fast path if direct pointer available
    const uint8_t* ptr = reader_->directPointer(abs_off, 256);
    if (ptr) {
        return std::string(reinterpret_cast<const char*>(ptr));
    }

    // Read byte by byte or in small chunks
    std::string result;
    char ch = 0;
    while (abs_off < reader_->size()) {
        if (!reader_->read(abs_off++, &ch, 1) || ch == 0) break;
        result.push_back(ch);
        if (result.size() > 512) break; // Limit safety
    }
    return result;
}

bool ConverterBundle::readModelIndexEntry(uint32_t index, IndexEntry& entry) const {
    if (!valid_ || !reader_ || index >= header_.model_idx_count) return false;
    size_t off = header_.model_idx_offset + index * INDEX_ENTRY_SIZE;
    return reader_->read(off, &entry, sizeof(entry));
}

bool ConverterBundle::isAmbiguousModel(const std::string& model) const {
    if (!valid_ || !reader_ || model.empty()) return false;
    const uint32_t target_hash = hash_fnv1a(model);
    int32_t low = 0;
    int32_t high = static_cast<int32_t>(header_.model_idx_count) - 1;
    int32_t first = -1;

    while (low <= high) {
        const int32_t mid = low + (high - low) / 2;
        IndexEntry entry{};
        if (!readModelIndexEntry(static_cast<uint32_t>(mid), entry)) return false;
        if (entry.hash == target_hash) {
            first = mid;
            high = mid - 1;
        } else if (entry.hash < target_hash) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    for (int32_t i = first; i >= 0 && i < static_cast<int32_t>(header_.model_idx_count); ++i) {
        IndexEntry entry{};
        if (!readModelIndexEntry(static_cast<uint32_t>(i), entry) || entry.hash != target_hash) break;
        if ((entry.flags & FLAG_AMBIGUOUS_MODEL) != 0) return true;
    }
    return false;
}

bool ConverterBundle::readFpIndexEntry(uint32_t index, IndexEntry& entry) const {
    if (!valid_ || !reader_ || index >= header_.fp_idx_count) return false;
    size_t off = header_.fp_idx_offset + index * INDEX_ENTRY_SIZE;
    return reader_->read(off, &entry, sizeof(entry));
}

bool ConverterBundle::readFingerprintConstraint(uint32_t index, FingerprintConstraint& constraint) const {
    if (!valid_ || !reader_ || header_.version < LEGACY_V5_FORMAT_VERSION ||
        index >= header_.fp_constraints_count) {
        return false;
    }
    const bool is_v7 = header_.version >= LEGACY_V7_FORMAT_VERSION;
    const size_t record_size = is_v7 ? FINGERPRINT_CONSTRAINT_SIZE : LEGACY_V6_CONSTRAINT_SIZE;
    const size_t off = header_.fp_constraints_offset + index * record_size;
    std::memset(&constraint, 0, sizeof(constraint));
    // v5/v6 constraints are the v7 record minus the trailing strict-string
    // offsets; read the common prefix so older bundles still resolve.
    return reader_->read(off, &constraint, record_size);
}

bool ConverterBundle::readFingerprintEndpoint(uint32_t index, FingerprintEndpoint& endpoint) const {
    if (!valid_ || !reader_ || header_.version < LEGACY_V6_FORMAT_VERSION) return false;
    const uint32_t endpoint_offset = readLe32(&header_.reserved[0]);
    const uint32_t endpoint_count = readLe32(&header_.reserved[4]);
    if (index >= endpoint_count) return false;
    const size_t off = endpoint_offset + index * FINGERPRINT_ENDPOINT_SIZE;
    return reader_->read(off, &endpoint, sizeof(endpoint));
}

bool ConverterBundle::readFingerprintCluster(uint32_t index, uint16_t& cluster) const {
    if (!valid_ || !reader_ || header_.version < LEGACY_V6_FORMAT_VERSION) return false;
    const uint32_t cluster_offset = readLe32(&header_.reserved[8]);
    const uint32_t cluster_count = readLe32(&header_.reserved[12]);
    if (index >= cluster_count) return false;
    return reader_->read(cluster_offset + index * sizeof(uint16_t), &cluster, sizeof(cluster));
}

bool ConverterBundle::readWhiteLabel(uint32_t index, WhiteLabelIR& white_label) const {
    if (!valid_ || !reader_ || header_.version < LEGACY_V6_FORMAT_VERSION) return false;
    const uint32_t white_label_offset = readLe32(&header_.reserved[16]);
    const uint32_t white_label_count = readLe32(&header_.reserved[20]);
    if (index >= white_label_count) return false;
    return reader_->read(white_label_offset + index * sizeof(WhiteLabelIR),
                         &white_label, sizeof(white_label));
}

bool ConverterBundle::readRecordHeader(uint32_t record_offset, RecordHeader& header) const {
    if (!valid_ || !reader_) return false;
    const size_t records_size = header_.strings_offset - header_.records_offset;
    if (record_offset > records_size || sizeof(RecordHeader) > records_size - record_offset) {
        return false;
    }
    size_t abs_off = header_.records_offset + record_offset;
    return reader_->read(abs_off, &header, sizeof(header));
}

bool ConverterBundle::readRecordV8Extension(uint32_t record_offset,
                                            RecordV8Extension& extension) const {
    if (!valid_ || !reader_ || header_.version < LEGACY_V8_FORMAT_VERSION) return false;
    const size_t records_size = header_.strings_offset - header_.records_offset;
    if (record_offset > records_size ||
        records_size - record_offset < sizeof(RecordHeader) + sizeof(RecordV8Extension)) {
        return false;
    }
    return reader_->read(header_.records_offset + record_offset + sizeof(RecordHeader),
                         &extension, sizeof(extension));
}

bool ConverterBundle::readRecordV9Extension(uint32_t record_offset,
                                            RecordV9Extension& extension) const {
    if (!valid_ || !reader_ || header_.version < LEGACY_V9_FORMAT_VERSION) return false;
    const size_t records_size = record_data_size_ != 0
        ? record_data_size_
        : header_.strings_offset - header_.records_offset;
    const size_t ext_offset = sizeof(RecordHeader) + sizeof(RecordV8Extension);
    if (record_offset > records_size ||
        records_size - record_offset < ext_offset + sizeof(RecordV9Extension)) {
        return false;
    }
    return reader_->read(header_.records_offset + record_offset + ext_offset,
                         &extension, sizeof(extension));
}

bool ConverterBundle::readRecordV9MultiEndpoint(
    uint32_t record_offset, RecordV9MultiEndpoint& metadata) const {
    if (!valid_ || !reader_ || header_.version < LEGACY_V9_FORMAT_VERSION) return false;
    RecordV9Extension ext{};
    if (!readRecordV9Extension(record_offset, ext)) return false;
    if ((ext.flags & RECORD_V9_FLAG_MULTI_ENDPOINT) == 0) return false;

    RecordV8Extension declared{};
    if (!readRecordV8Extension(record_offset, declared)) return false;
    const size_t records_size = record_data_size_ != 0
        ? record_data_size_
        : header_.strings_offset - header_.records_offset;
    if (record_offset > records_size || declared.declared_models_count > 256) {
        return false;
    }
    const size_t declared_bytes =
        static_cast<size_t>(declared.declared_models_count) * sizeof(uint32_t);
    if (declared.declared_models_offset > records_size ||
        declared_bytes > records_size - declared.declared_models_offset) {
        return false;
    }
    // Both offsets are relative to the records section.
    const size_t metadata_offset = declared.declared_models_offset + declared_bytes;
    if (metadata_offset > records_size ||
        records_size - metadata_offset < sizeof(RecordV9MultiEndpoint)) {
        return false;
    }
    RecordV9MultiEndpoint read_metadata{};
    if (!reader_->read(header_.records_offset + metadata_offset,
                       &read_metadata, sizeof(read_metadata))) {
        return false;
    }
    const size_t expected_skip_offset =
        metadata_offset + sizeof(RecordV9MultiEndpoint);
    if (read_metadata.skip_offset != expected_skip_offset) return false;
    metadata = read_metadata;
    return true;
}

bool ConverterBundle::readVmInstruction(uint32_t program_offset, uint32_t program_size,
                                        uint32_t instruction_index,
                                        VmInstruction& instruction) const {
    if (!valid_ || !reader_ || header_.version < LEGACY_V9_FORMAT_VERSION) return false;
    if (program_size == 0 || program_size % VM_INSTRUCTION_SIZE != 0 ||
        program_offset > vm_code_size_ || program_size > vm_code_size_ - program_offset ||
        instruction_index >= program_size / VM_INSTRUCTION_SIZE) {
        return false;
    }
    return reader_->read(vm_code_offset_ + program_offset +
                         instruction_index * VM_INSTRUCTION_SIZE,
                         &instruction, sizeof(instruction));
}

bool ConverterBundle::readRecordDeclaredModels(uint32_t record_offset,
                                               std::vector<std::string>& models) const {
    models.clear();
    if (!valid_ || !reader_ || header_.version < LEGACY_V8_FORMAT_VERSION) return false;
    if (header_.records_offset > header_.strings_offset) return false;
    const size_t records_size = record_data_size_ != 0
        ? record_data_size_
        : header_.strings_offset - header_.records_offset;
    if (record_offset > records_size ||
        records_size - record_offset < sizeof(RecordHeader) + sizeof(RecordV8Extension)) {
        return false;
    }

    RecordV8Extension ext{};
    const size_t ext_off = header_.records_offset + record_offset + sizeof(RecordHeader);
    if (!reader_->read(ext_off, &ext, sizeof(ext))) return false;
    if (ext.declared_models_count == 0) return true;
    if (ext.declared_models_count > 256) return false;
    const size_t declared_bytes =
        static_cast<size_t>(ext.declared_models_count) * sizeof(uint32_t);
    if (ext.declared_models_offset > records_size ||
        declared_bytes > records_size - ext.declared_models_offset) {
        return false;
    }

    const size_t list_off = header_.records_offset + ext.declared_models_offset;
    models.reserve(ext.declared_models_count);
    for (uint32_t i = 0; i < ext.declared_models_count; ++i) {
        uint32_t str_offset = 0;
        if (!reader_->read(list_off + i * sizeof(uint32_t), &str_offset, sizeof(str_offset))) {
            models.clear();
            return false;
        }
        models.push_back(getString(str_offset));
    }
    return true;
}

bool ConverterBundle::recordDeclaresModel(uint32_t record_offset,
                                          const std::string& exact_model,
                                          const std::string& normalized_model) const {
    if (exact_model.empty() && normalized_model.empty()) return false;
    std::vector<std::string> declared;
    if (!readRecordDeclaredModels(record_offset, declared)) return false;
    for (const std::string& model : declared) {
        if (model == exact_model) return true;
        if (!normalized_model.empty() && model == normalized_model) return true;
    }
    return false;
}

bool ConverterBundle::readRecordV10BatterySemantics(
    uint32_t record_offset, RecordV10BatterySemantics& semantics) const {
    if (!valid_ || !reader_ || header_.version < FORMAT_VERSION) return false;
    const size_t records_size = record_data_size_ != 0
        ? record_data_size_
        : header_.strings_offset - header_.records_offset;
    const size_t ext_offset = sizeof(RecordHeader) + sizeof(RecordV8Extension) +
                              sizeof(RecordV9Extension);
    if (record_offset > records_size ||
        records_size - record_offset < ext_offset + sizeof(RecordV10BatterySemantics)) {
        return false;
    }
    return reader_->read(header_.records_offset + record_offset + ext_offset,
                         &semantics, sizeof(semantics));
}

} // namespace z2m
