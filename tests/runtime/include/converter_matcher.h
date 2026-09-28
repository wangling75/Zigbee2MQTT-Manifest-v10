#pragma once

#include "converter_bundle.h"
#include "converter_types.h"

namespace z2m {

enum class MatchSource : uint8_t {
    NONE = 0,
    EXACT_FINGERPRINT,
    SOLE_MODEL,
    MODEL_FALLBACK,
    GENERIC_CAPABILITY
};

struct MatchedConverter {
    bool matched = false;
    IndexEntry index_entry;
    // How the definition was selected. A model fallback is a real
    // official definition, but it is not proof that a shared modelID
    // uniquely identifies this physical device.
    MatchSource match_source = MatchSource::NONE;
    RecordHeader record_header;
    std::string model;
    std::string vendor;
    std::string description;
    DeviceCategory category = DeviceCategory::GENERIC;
    // True when this came from a real bundle record rather than the
    // generic On/Off fallback synthesized by the matcher.
    bool category_authoritative = false;
    std::vector<EndpointDesc> endpoints;
    std::vector<FromZigbeeIR> fz_rules;
    std::vector<ToZigbeeIR> tz_rules;
    std::vector<TuyaDpIR> tuya_dps;
    std::vector<VmInstruction> from_program;
    std::vector<VmInstruction> to_program;
    std::vector<ReportingConfig> reporting_configs;
    std::vector<uint16_t> binds;
    RecordV10BatterySemantics battery_semantics{};
    bool has_battery_semantics = false;
};

class ConverterMatcher {
public:
    bool findSoleModelCandidate(const std::string& model, IndexEntry& out_entry, uint32_t* seek_count = nullptr);
    explicit ConverterMatcher(const ConverterBundle& bundle);

    // Matches using the official ZHC order:
    // 1. modelID candidates, then highest-priority matching fingerprint
    // 2. first matching zigbeeModel in official MODELS_INDEX order
    // 3. standard On/Off capability fallback
    bool matchDevice(const DeviceInterview& interview, MatchedConverter& out_converter);

    // Direct binary search by model ID.
    bool findByModel(const std::string& model, IndexEntry& out_entry, uint32_t* seek_count = nullptr);
    bool isAmbiguousModel(const std::string& model) const { return bundle_.isAmbiguousModel(model); }

    // Direct binary search by fingerprint (mfg + "|" + model).
    bool findByFingerprint(const std::string& mfg, const std::string& model, IndexEntry& out_entry,
                           uint32_t* seek_count = nullptr, uint16_t manufacturer_code = 0,
                           const std::string& date_code = "", const std::string& software_build_id = "",
                           uint8_t logical_type = 0, uint8_t power_source = 0xFF,
                           int16_t application_version = -1, int16_t hardware_version = -1,
                           int16_t stack_version = -1, int16_t zcl_version = -1,
                           uint64_t ieee_addr = 0,
                           const std::vector<EndpointInfo>& endpoints = {});

    // Load full converter record details into memory.
    bool loadRecordDetails(const IndexEntry& entry, MatchedConverter& out_converter);

    // Apply the first matching official white-label override, if any.
    bool applyWhiteLabel(const DeviceInterview& interview, MatchedConverter& out_converter);

private:
    const ConverterBundle& bundle_;
};

} // namespace z2m
