#pragma once

#include "converter_types.h"
#include <memory>
#include <cstdio>

namespace z2m {

class IBundleReader {
public:
    virtual ~IBundleReader() = default;
    virtual bool read(size_t offset, void* dest, size_t size) = 0;
    virtual size_t size() const = 0;
    virtual const uint8_t* directPointer(size_t /*offset*/, size_t /*size*/) const { return nullptr; }
};

// Zero-copy in-memory or flash memory-mapped bundle reader
class MemoryBundleReader : public IBundleReader {
public:
    MemoryBundleReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    bool read(size_t offset, void* dest, size_t size) override {
        if (!data_ || !dest || offset > size_ || size > size_ - offset) return false;
        std::memcpy(dest, data_ + offset, size);
        return true;
    }

    size_t size() const override { return size_; }
    const uint8_t* directPointer(size_t offset, size_t size) const override {
        if (!data_ || offset > size_ || size > size_ - offset) return nullptr;
        return data_ + offset;
    }

private:
    const uint8_t* data_;
    size_t size_;
};

// File-based bundle reader (for host unit tests / LittleFS / SPIFFS)
class FileBundleReader : public IBundleReader {
public:
    explicit FileBundleReader(const std::string& path);
    ~FileBundleReader() override;

    bool isOpen() const { return file_ != nullptr; }
    bool read(size_t offset, void* dest, size_t size) override;
    size_t size() const override { return size_; }

private:
    FILE* file_ = nullptr;
    size_t size_ = 0;
};

class ConverterBundle {
public:
    ConverterBundle() = default;
    ~ConverterBundle() = default;

    bool load(std::shared_ptr<IBundleReader> reader);
    bool isValid() const { return valid_; }

    const BundleHeader& header() const { return header_; }
    std::string getString(uint32_t offset) const;

    bool readModelIndexEntry(uint32_t index, IndexEntry& entry) const;
    bool isAmbiguousModel(const std::string& model) const;
    bool readFpIndexEntry(uint32_t index, IndexEntry& entry) const;
    bool readFingerprintConstraint(uint32_t index, FingerprintConstraint& constraint) const;
    bool readFingerprintEndpoint(uint32_t index, FingerprintEndpoint& endpoint) const;
    bool readFingerprintCluster(uint32_t index, uint16_t& cluster) const;
    bool readWhiteLabel(uint32_t index, WhiteLabelIR& white_label) const;
    bool readRecordHeader(uint32_t record_offset, RecordHeader& header) const;
    bool readRecordV9Extension(uint32_t record_offset, RecordV9Extension& extension) const;
    bool readRecordV9MultiEndpoint(uint32_t record_offset,
                                   RecordV9MultiEndpoint& metadata) const;
    bool readRecordV10BatterySemantics(
        uint32_t record_offset, RecordV10BatterySemantics& semantics) const;
    bool readRecordV8Extension(uint32_t record_offset, RecordV8Extension& extension) const;
    bool readVmInstruction(uint32_t program_offset, uint32_t program_size,
                           uint32_t instruction_index, VmInstruction& instruction) const;
    bool readRecordDeclaredModels(uint32_t record_offset, std::vector<std::string>& models) const;
    bool recordDeclaresModel(uint32_t record_offset, const std::string& exact_model,
                             const std::string& normalized_model) const;

    uint32_t vmCodeOffset() const { return vm_code_offset_; }
    uint32_t vmCodeSize() const { return vm_code_size_; }
    uint32_t recordDataSize() const { return record_data_size_; }
    uint32_t vmProgramCount() const { return vm_program_count_; }
    uint16_t requiredCapabilities() const { return required_capabilities_; }

    std::shared_ptr<IBundleReader> reader() const { return reader_; }

private:
    std::shared_ptr<IBundleReader> reader_;
    BundleHeader header_;
    uint32_t vm_code_offset_ = 0;
    uint32_t vm_code_size_ = 0;
    uint32_t record_data_size_ = 0;
    uint32_t vm_program_count_ = 0;
    uint16_t required_capabilities_ = 0;
    bool valid_ = false;
};

} // namespace z2m
