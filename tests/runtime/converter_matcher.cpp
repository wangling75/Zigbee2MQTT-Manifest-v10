#include "converter_matcher.h"
#include <cstdio>
#include <algorithm>

namespace z2m {

namespace {

bool endpointIdListMatches(const std::vector<EndpointInfo>& device_endpoints,
                           const std::vector<uint16_t>& expected_ids) {
    if (device_endpoints.size() != expected_ids.size()) return false;
    for (size_t i = 0; i < device_endpoints.size(); ++i) {
        if (device_endpoints[i].ep_id != expected_ids[i]) return false;
    }
    return true;
}

bool clusterListMatches(const std::vector<uint16_t>& actual,
                        const std::vector<uint16_t>& expected) {
    return actual == expected;
}

bool ieeeRegexMatches(const std::string& pattern, uint64_t ieee_addr) {
    // ZHC fingerprints currently use only anchored expressions of the form
    // ^0x[0-9a-f.]{n}$ (optionally with a literal suffix). Implement that
    // complete subset without pulling a general regex engine into firmware.
    if (pattern.size() < 3 || pattern.front() != '^' || pattern.back() != '$') {
        return false;
    }
    const std::string body = pattern.substr(1, pattern.size() - 2);
    if (body.size() < 2 || body[0] != '0' || (body[1] != 'x' && body[1] != 'X')) {
        return false;
    }
    char address[19];
    snprintf(address, sizeof(address), "0x%016llx",
             static_cast<unsigned long long>(ieee_addr));
    const std::string actual(address);

    size_t body_pos = 2;
    size_t actual_pos = 2;
    while (body_pos < body.size() && actual_pos < actual.size()) {
        const char token = body[body_pos];
        if (token == '.') {
            ++body_pos;
            ++actual_pos;
            continue;
        }
        if (actual[actual_pos] != token) return false;
        ++body_pos;
        ++actual_pos;
    }
    return body_pos == body.size() && actual_pos == actual.size();
}

std::string normalizeModelKey(std::string model) {
    const size_t nul = model.find('\0');
    if (nul != std::string::npos) model.resize(nul);
    const size_t begin = model.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    const size_t end = model.find_last_not_of(" \t\r\n");
    return model.substr(begin, end - begin + 1);
}

} // namespace

ConverterMatcher::ConverterMatcher(const ConverterBundle& bundle) : bundle_(bundle) {}

bool ConverterMatcher::findSoleModelCandidate(const std::string& model, IndexEntry& out_entry,
                                             uint32_t* seek_count) {
    if (!bundle_.isValid() || model.empty()) return false;

    const uint32_t exact_hash = hash_fnv1a(model);
    const std::string normalized = normalizeModelKey(model);
    const uint32_t normalized_hash = hash_fnv1a(normalized);
    uint32_t seeks = 0;
    bool found = false;
    IndexEntry sole{};

    auto keyExists = [&](uint32_t target_hash) -> bool {
        int32_t low = 0;
        int32_t high = static_cast<int32_t>(bundle_.header().model_idx_count) - 1;
        while (low <= high) {
            const int32_t mid = low + (high - low) / 2;
            seeks++;
            IndexEntry entry{};
            if (!bundle_.readModelIndexEntry(static_cast<uint32_t>(mid), entry)) return false;
            if (entry.hash == target_hash) {
                if (bundle_.header().version < LEGACY_V6_FORMAT_VERSION) return true;
                int32_t first = mid;
                while (first > 0) {
                    IndexEntry prev{};
                    seeks++;
                    if (!bundle_.readModelIndexEntry(static_cast<uint32_t>(first - 1), prev) ||
                        prev.hash != target_hash) break;
                    --first;
                }
                for (int32_t i = first; i < static_cast<int32_t>(bundle_.header().model_idx_count); ++i) {
                    IndexEntry current{};
                    seeks++;
                    if (!bundle_.readModelIndexEntry(static_cast<uint32_t>(i), current) ||
                        current.hash != target_hash) break;
                    if ((current.flags & FLAG_MODEL_EXACT_KEY) != 0) return true;
                }
                return false;
            }
            if (entry.hash < target_hash) low = mid + 1;
            else high = mid - 1;
        }
        return false;
    };

    const bool exact_key_present = keyExists(exact_hash);

    auto scanKey = [&](uint32_t target_hash, bool exact_key) {
        if (found || target_hash == 0) return;
        int32_t low = 0;
        int32_t high = static_cast<int32_t>(bundle_.header().model_idx_count) - 1;
        int32_t first = -1;
        while (low <= high) {
            const int32_t mid = low + (high - low) / 2;
            seeks++;
            IndexEntry entry{};
            if (!bundle_.readModelIndexEntry(static_cast<uint32_t>(mid), entry)) return;
            if (entry.hash == target_hash) {
                first = mid;
                high = mid - 1;
            } else if (entry.hash < target_hash) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        if (first < 0) return;

        int count = 0;
        bool candidate_has_zigbee_model = false;
        IndexEntry candidate{};
        for (int32_t i = first; i >= 0 && i < static_cast<int32_t>(bundle_.header().model_idx_count); ++i) {
            IndexEntry entry{};
            seeks++;
            if (!bundle_.readModelIndexEntry(static_cast<uint32_t>(i), entry) || entry.hash != target_hash) break;
            // ZHC counts the complete candidate list before deciding
            // whether it is safe to return a sole zigbeeModel candidate.
            // A fingerprint-only definition in the same key still makes
            // the result ambiguous and must be resolved by fingerprint.
            if (bundle_.header().version >= LEGACY_V6_FORMAT_VERSION) {
                const bool is_exact = (entry.flags & FLAG_MODEL_EXACT_KEY) != 0;
                if (exact_key && !is_exact) continue;
                if (!exact_key && is_exact) continue;
            }
            if (++count > 1) return;
            candidate = entry;
            candidate_has_zigbee_model =
                (entry.flags & FLAG_HAS_ZIGBEE_MODEL) != 0;
        }
        if (count == 1 && candidate_has_zigbee_model) {
            sole = candidate;
            found = true;
        }
    };

    // Match ZHC getFromIndex(): an exact key short-circuits the normalized
    // key entirely, even when it has no sole zigbeeModel candidate.
    if (exact_key_present) {
        scanKey(exact_hash, true);
    } else if (normalized_hash != exact_hash) {
        scanKey(normalized_hash, false);
    }

    if (seek_count) *seek_count = seeks;
    if (found) out_entry = sole;
    return found;
}

bool ConverterMatcher::findByModel(const std::string& model, IndexEntry& out_entry, uint32_t* seek_count) {
    if (!bundle_.isValid() || model.empty()) return false;
    // ZHC returns the sole declared zigbeeModel candidate immediately,
    // before evaluating its fingerprint constraints.
    if (findSoleModelCandidate(model, out_entry, seek_count)) return true;
    const uint32_t exact_hash = hash_fnv1a(model);
    const std::string normalized = normalizeModelKey(model);
    const uint32_t normalized_hash = hash_fnv1a(normalized);

    uint32_t seeks = 0;
    bool found = false;
    IndexEntry best{};
    int32_t best_rank = 0x7FFF;
    uint32_t best_record_offset = 0xFFFFFFFFu;
    int32_t best_key_rank = 0x7FFFFFFF;

    auto scanKey = [&](uint32_t target_hash, int32_t key_rank) {
        int32_t low = 0;
        int32_t high = static_cast<int32_t>(bundle_.header().model_idx_count) - 1;
        int32_t first = -1;
        while (low <= high) {
            int32_t mid = low + (high - low) / 2;
            seeks++;
            IndexEntry entry;
            if (!bundle_.readModelIndexEntry(mid, entry)) return;
            if (entry.hash == target_hash) {
                first = mid;
                high = mid - 1;
            } else if (entry.hash < target_hash) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        for (int32_t i = first; i >= 0 && i < static_cast<int32_t>(bundle_.header().model_idx_count); ++i) {
            IndexEntry entry;
            seeks++;
            if (!bundle_.readModelIndexEntry(i, entry) || entry.hash != target_hash) break;
            if ((entry.flags & FLAG_MODEL_FALLBACK) == 0) continue;
            if (bundle_.header().version >= LEGACY_V6_FORMAT_VERSION &&
                (entry.flags & FLAG_HAS_ZIGBEE_MODEL) == 0) continue;
            // v8 added the declared-zigbeeModel table precisely so this
            // strict comparison can run. Gating it on v9 let every v8
            // fallback candidate match regardless of its declared models,
            // so an unknown "CCT Light" resolved to Paulmann 50064 (whose
            // declared models are "CCT light"/"CCT_light") instead of
            // staying unresolved.
            if (bundle_.header().version >= LEGACY_V8_FORMAT_VERSION &&
                !bundle_.recordDeclaresModel(entry.record_offset, model, normalized)) continue;
            if (bundle_.header().version >= LEGACY_V6_FORMAT_VERSION) {
                const bool exact_key = (entry.flags & FLAG_MODEL_EXACT_KEY) != 0;
                if (key_rank == 0 && !exact_key) continue;
                if (key_rank == 1 && exact_key) continue;
            }

            const int32_t candidate_rank =
                bundle_.header().version >= LEGACY_V6_FORMAT_VERSION ? static_cast<int32_t>(entry.extra) : 0;
            if (!found || key_rank < best_key_rank ||
                (key_rank == best_key_rank && (candidate_rank < best_rank ||
                 (candidate_rank == best_rank && entry.record_offset < best_record_offset)))) {
                best = entry;
                best_rank = candidate_rank;
                best_record_offset = entry.record_offset;
                best_key_rank = key_rank;
                found = true;
            }
        }
    };

    // Match ZHC getFromIndex(): exact key existence suppresses normalized
    // key candidates, regardless of whether an exact candidate is fallback
    // eligible.
    bool exact_key_present = false;
    {
        int32_t low = 0;
        int32_t high = static_cast<int32_t>(bundle_.header().model_idx_count) - 1;
        while (low <= high) {
            const int32_t mid = low + (high - low) / 2;
            seeks++;
            IndexEntry entry{};
            if (!bundle_.readModelIndexEntry(static_cast<uint32_t>(mid), entry)) break;
            if (entry.hash == exact_hash) {
                exact_key_present = true;
                break;
            }
            if (entry.hash < exact_hash) low = mid + 1;
            else high = mid - 1;
        }
    }
    if (exact_key_present) {
        scanKey(exact_hash, 0);
    } else if (normalized_hash != exact_hash) {
        scanKey(normalized_hash, 1);
    }

    if (found) out_entry = best;
    if (seek_count) *seek_count = seeks;
    return found;
}

bool ConverterMatcher::findByFingerprint(const std::string& mfg, const std::string& model, IndexEntry& out_entry,
                                         uint32_t* seek_count, uint16_t manufacturer_code,
                                         const std::string& date_code, const std::string& software_build_id,
                                         uint8_t logical_type, uint8_t power_source,
                                         int16_t application_version, int16_t hardware_version,
                                         int16_t stack_version, int16_t zcl_version,
                                         uint64_t ieee_addr,
                                         const std::vector<EndpointInfo>& endpoints) {
    if (!bundle_.isValid() || (mfg.empty() && model.empty())) return false;

    bool found = false;
    IndexEntry best{};
    int16_t best_priority = -32768;
    uint32_t seeks = 0;
    int32_t best_model_priority = 0x7FFF;
    uint32_t best_source_order = 0xFFFFFFFFu;
    uint32_t best_record_offset = 0xFFFFFFFFu;

    auto fpKeyExists = [&](uint32_t target_hash) -> bool {
        int32_t low = 0;
        int32_t high = static_cast<int32_t>(bundle_.header().fp_idx_count) - 1;
        while (low <= high) {
            const int32_t mid = low + (high - low) / 2;
            seeks++;
            IndexEntry entry{};
            if (!bundle_.readFpIndexEntry(static_cast<uint32_t>(mid), entry)) return false;
            if (entry.hash == target_hash) return true;
            if (entry.hash < target_hash) low = mid + 1;
            else high = mid - 1;
        }
        return false;
    };

    auto scanKey = [&](uint32_t target_hash) {
        int32_t low = 0;
        int32_t high = static_cast<int32_t>(bundle_.header().fp_idx_count) - 1;
        int32_t first = -1;

        while (low <= high) {
            int32_t mid = low + (high - low) / 2;
            seeks++;
            IndexEntry entry;
            if (!bundle_.readFpIndexEntry(mid, entry)) return;

            if (entry.hash == target_hash) {
                first = mid;
                high = mid - 1;
            } else if (entry.hash < target_hash) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        for (int32_t i = first; i >= 0 && i < static_cast<int32_t>(bundle_.header().fp_idx_count); ++i) {
            IndexEntry entry;
            seeks++;
            if (!bundle_.readFpIndexEntry(i, entry) || entry.hash != target_hash) break;

            int16_t candidate_priority = 0;
            int32_t candidate_model_priority = 0x7FFF;
            uint32_t candidate_source_order = 0;
            if (bundle_.header().version >= LEGACY_V5_FORMAT_VERSION) {
                if (entry.extra >= bundle_.header().fp_constraints_count) continue;
                FingerprintConstraint constraint{};
                if (!bundle_.readFingerprintConstraint(static_cast<uint32_t>(entry.extra), constraint)) {
                    continue;
                }
                candidate_priority = constraint.priority;
                candidate_model_priority = static_cast<int32_t>(constraint.model_priority);
                candidate_source_order = constraint.source_order;
                if (constraint.fp_hash != target_hash || constraint.record_offset != entry.record_offset) {
                    continue;
                }
                // v7: the fingerprint index key is lower-cased, but ZHC
                // compares manufacturerName/modelID with strict ===. Compare
                // the exact declared strings so case differences and embedded
                // NULs cannot collapse two distinct fingerprints into one.
                if (bundle_.header().version >= LEGACY_V7_FORMAT_VERSION) {
                    if (constraint.mfg_str_offset != 0 &&
                        bundle_.getString(constraint.mfg_str_offset) != mfg) {
                        continue;
                    }
                    if (constraint.model_str_offset != 0 &&
                        bundle_.getString(constraint.model_str_offset) != model) {
                        continue;
                    }
                }
                if ((constraint.flags & FP_FLAG_MANUFACTURER_CODE) != 0 &&
                    (manufacturer_code == 0 || constraint.manufacturer_code != manufacturer_code)) {
                    continue;
                }
                if (constraint.type != 0 && constraint.type != logical_type) continue;
                if (constraint.power_source != 0xFF && constraint.power_source != power_source) continue;
                if (constraint.date_str_offset != 0 &&
                    bundle_.getString(constraint.date_str_offset) != date_code) {
                    continue;
                }
                if (constraint.sw_str_offset != 0 &&
                    bundle_.getString(constraint.sw_str_offset) != software_build_id) {
                    continue;
                }
                if (constraint.application_version >= 0 &&
                    constraint.application_version != application_version) continue;
                if (constraint.hardware_version >= 0 &&
                    constraint.hardware_version != hardware_version) continue;
                if (constraint.stack_version >= 0 &&
                    constraint.stack_version != stack_version) continue;
                if (constraint.zcl_version >= 0 &&
                    constraint.zcl_version != zcl_version) continue;
                if ((constraint.flags & FP_FLAG_IEEE_ADDR) != 0) {
                    const std::string pattern = bundle_.getString(constraint.ieee_str_offset);
                    if (pattern.empty() || !ieeeRegexMatches(pattern, ieee_addr)) continue;
                }
                if ((constraint.flags & FP_FLAG_ENDPOINTS) != 0) {
                    if (endpoints.empty() || constraint.endpoint_count == 0) continue;
                    std::vector<uint16_t> expected_ids;
                    expected_ids.reserve(constraint.endpoint_count);
                    bool endpoints_match = true;
                    for (uint8_t ep_index = 0; ep_index < constraint.endpoint_count; ++ep_index) {
                        FingerprintEndpoint expected{};
                        if (!bundle_.readFingerprintEndpoint(
                                constraint.endpoint_offset + ep_index, expected)) {
                            endpoints_match = false;
                            break;
                        }
                        expected_ids.push_back(expected.id);
                        const EndpointInfo* actual = nullptr;
                        for (const auto& ep : endpoints) {
                            if (ep.ep_id == expected.id) {
                                actual = &ep;
                                break;
                            }
                        }
                        if (!actual) {
                            endpoints_match = false;
                            break;
                        }
                        if ((expected.flags & 0x01) != 0 && actual->profile_id != expected.profile_id) {
                            endpoints_match = false;
                            break;
                        }
                        if ((expected.flags & 0x02) != 0 && actual->device_id != expected.device_id) {
                            endpoints_match = false;
                            break;
                        }
                        if ((expected.flags & 0x04) != 0) {
                            std::vector<uint16_t> expected_clusters;
                            expected_clusters.reserve(expected.input_count);
                            for (uint16_t c = 0; c < expected.input_count; ++c) {
                                uint16_t cluster = 0;
                                if (!bundle_.readFingerprintCluster(
                                        expected.input_offset + c, cluster)) {
                                    endpoints_match = false;
                                    break;
                                }
                                expected_clusters.push_back(cluster);
                            }
                            if (!endpoints_match ||
                                !clusterListMatches(actual->input_clusters, expected_clusters)) {
                                endpoints_match = false;
                                break;
                            }
                        }
                        if ((expected.flags & 0x08) != 0) {
                            std::vector<uint16_t> expected_clusters;
                            expected_clusters.reserve(expected.output_count);
                            for (uint16_t c = 0; c < expected.output_count; ++c) {
                                uint16_t cluster = 0;
                                if (!bundle_.readFingerprintCluster(
                                        expected.output_offset + c, cluster)) {
                                    endpoints_match = false;
                                    break;
                                }
                                expected_clusters.push_back(cluster);
                            }
                            if (!endpoints_match ||
                                !clusterListMatches(actual->output_clusters, expected_clusters)) {
                                endpoints_match = false;
                                break;
                            }
                        }
                    }
                    if (!endpoints_match || !endpointIdListMatches(endpoints, expected_ids)) continue;
                }
            } else {
                if (entry.extra != 0 &&
                    (manufacturer_code == 0 ||
                     static_cast<uint16_t>(entry.extra) != manufacturer_code)) {
                    continue;
                }
            }

            // ZHC replaces the current match only when the candidate
            // priority is strictly greater. Equal-priority matches keep the
            // first fingerprint in official candidate/declaration order.
            const bool replaces = !found ||
                candidate_priority > best_priority ||
                (candidate_priority == best_priority &&
                 (candidate_model_priority < best_model_priority ||
                  (candidate_model_priority == best_model_priority &&
                   (candidate_source_order < best_source_order ||
                    (candidate_source_order == best_source_order &&
                     entry.record_offset < best_record_offset)))));
            if (replaces) {
                best = entry;
                best_priority = candidate_priority;
                best_model_priority = candidate_model_priority;
                best_source_order = candidate_source_order;
                best_record_offset = entry.record_offset;
                found = true;
            }
        }
    };

    const std::string exact_key = mfg + "|" + model;
    const uint32_t exact_hash = hash_fnv1a(exact_key);
    if (fpKeyExists(exact_hash)) {
        scanKey(exact_hash);
    } else if (!mfg.empty()) {
        const std::string normalized_key = "|" + model;
        const uint32_t normalized_hash = hash_fnv1a(normalized_key);
        if (normalized_hash != exact_hash) scanKey(normalized_hash);
    }

    if (found) out_entry = best;
    if (seek_count) *seek_count = seeks;
    return found;
}

bool ConverterMatcher::loadRecordDetails(const IndexEntry& entry, MatchedConverter& out_converter) {
    if (!bundle_.isValid()) return false;

    out_converter.matched = true;
    out_converter.index_entry = entry;
    out_converter.category = static_cast<DeviceCategory>(entry.category);
    out_converter.category_authoritative = true;
    out_converter.from_program.clear();
    out_converter.to_program.clear();

    RecordHeader hdr;
    if (!bundle_.readRecordHeader(entry.record_offset, hdr)) {
        return false;
    }
    out_converter.record_header = hdr;
    out_converter.model = bundle_.getString(hdr.model_str_offset);
    out_converter.vendor = bundle_.getString(hdr.vendor_str_offset);
    out_converter.description = bundle_.getString(hdr.desc_str_offset);

    auto reader = bundle_.reader();
    if (!reader || bundle_.header().records_offset > bundle_.header().strings_offset ||
        entry.record_offset > bundle_.header().strings_offset - bundle_.header().records_offset) {
        return false;
    }
    const size_t records_size = bundle_.header().strings_offset - bundle_.header().records_offset;
    if (entry.record_len < sizeof(RecordHeader) ||
        entry.record_len > records_size - entry.record_offset) {
        return false;
    }
    const size_t record_end = bundle_.header().records_offset + entry.record_offset + entry.record_len;
    size_t cursor = bundle_.header().records_offset + entry.record_offset + sizeof(RecordHeader);

    // v8 and v9 extensions are fixed-size and appear before the declared
    // zigbeeModel table. Read them in wire order, then advance to the end of
    // the table so endpoint and rule offsets stay aligned.
    if (bundle_.header().version >= LEGACY_V8_FORMAT_VERSION) {
        cursor += sizeof(RecordV8Extension);
    }
    if (bundle_.header().version >= LEGACY_V9_FORMAT_VERSION) {
        RecordV9Extension vm_ext{};
        if (!bundle_.readRecordV9Extension(entry.record_offset, vm_ext)) return false;
        if (vm_ext.vm_version != VM_VERSION ||
            (vm_ext.flags & ~RECORD_V9_FLAG_MULTI_ENDPOINT) != 0) {
            return false;
        }
        cursor += sizeof(RecordV9Extension);

        auto load_program = [&](uint32_t offset, uint32_t size,
                                std::vector<VmInstruction>& out) -> bool {
            if (offset == VM_PROGRAM_ABSENT) return size == 0;
            if (size == 0 || size % VM_INSTRUCTION_SIZE != 0) return false;
            const uint32_t count = size / VM_INSTRUCTION_SIZE;
            out.resize(count);
            for (uint32_t i = 0; i < count; ++i) {
                if (!bundle_.readVmInstruction(offset, size, i, out[i])) {
                    out.clear();
                    return false;
                }
            }
            return true;
        };
        if (!load_program(vm_ext.from_program_offset, vm_ext.from_program_size,
                          out_converter.from_program) ||
            !load_program(vm_ext.to_program_offset, vm_ext.to_program_size,
                          out_converter.to_program)) {
            return false;
        }
    }

    if (bundle_.header().version >= FORMAT_VERSION) {
        if (!bundle_.readRecordV10BatterySemantics(entry.record_offset,
                                                    out_converter.battery_semantics)) {
            return false;
        }
        out_converter.has_battery_semantics =
            (out_converter.battery_semantics.flags & BATTERY_FLAG_ENABLED) != 0;
        cursor += sizeof(RecordV10BatterySemantics);
    }
    if (bundle_.header().version >= LEGACY_V8_FORMAT_VERSION) {
        RecordV8Extension declared{};
        if (!bundle_.readRecordV8Extension(entry.record_offset, declared)) return false;
        if (declared.declared_models_count > 256 ||
            declared.declared_models_offset > records_size ||
            static_cast<size_t>(declared.declared_models_count) * sizeof(uint32_t) >
                records_size - declared.declared_models_offset) {
            return false;
        }
        cursor = bundle_.header().records_offset +
                 declared.declared_models_offset +
                 static_cast<size_t>(declared.declared_models_count) * sizeof(uint32_t);
        if (cursor > record_end) return false;
    }

    if (bundle_.header().version >= LEGACY_V9_FORMAT_VERSION) {
        RecordV9Extension vm_ext{};
        if (!bundle_.readRecordV9Extension(entry.record_offset, vm_ext)) return false;
        if ((vm_ext.flags & RECORD_V9_FLAG_MULTI_ENDPOINT) != 0) {
            RecordV9MultiEndpoint multi_ep{};
            if (!bundle_.readRecordV9MultiEndpoint(entry.record_offset, multi_ep)) return false;
            if (multi_ep.skip_count > 256 ||
                multi_ep.skip_offset > records_size ||
                static_cast<size_t>(multi_ep.skip_count) * sizeof(uint32_t) >
                    records_size - multi_ep.skip_offset) {
                return false;
            }
            cursor = bundle_.header().records_offset +
                     multi_ep.skip_offset +
                     static_cast<size_t>(multi_ep.skip_count) * sizeof(uint32_t);
            if (cursor > record_end) return false;
        }
    }


    auto read_block = [&](void* dst, size_t bytes) -> bool {
        if (cursor > record_end || bytes > record_end - cursor) return false;
        if (!reader->read(cursor, dst, bytes)) return false;
        cursor += bytes;
        return true;
    };

    out_converter.endpoints.resize(hdr.ep_count);
    if (hdr.ep_count > 0) {
        if (!read_block(out_converter.endpoints.data(), hdr.ep_count * sizeof(EndpointDesc))) return false;
    }

    out_converter.fz_rules.resize(hdr.fz_count);
    if (hdr.fz_count > 0) {
        if (!read_block(out_converter.fz_rules.data(), hdr.fz_count * sizeof(FromZigbeeIR))) return false;
    }

    out_converter.tz_rules.resize(hdr.tz_count);
    if (hdr.tz_count > 0) {
        if (bundle_.header().version >= LEGACY_V4_FORMAT_VERSION) {
            if (!read_block(out_converter.tz_rules.data(), hdr.tz_count * sizeof(ToZigbeeIR))) return false;
        } else {
            std::vector<ToZigbeeIRV3> legacy(hdr.tz_count);
            if (!read_block(legacy.data(), hdr.tz_count * sizeof(ToZigbeeIRV3))) return false;
            for (size_t i = 0; i < legacy.size(); ++i) {
                ToZigbeeIR& dst = out_converter.tz_rules[i];
                const ToZigbeeIRV3& src = legacy[i];
                dst.op = src.op;
                dst.endpoint_id = src.endpoint_id;
                dst.cluster_id = src.cluster_id;
                dst.cmd_or_attr = src.cmd_or_attr;
                dst.cmd_on = src.cmd_on;
                dst.cmd_off = src.cmd_off;
                dst.target_str_offset = src.target_str_offset;
                dst.scale = src.scale;
                dst.datatype = static_cast<uint8_t>(DataType::INT16);
            }
        }
    }

    out_converter.tuya_dps.resize(hdr.dp_count);
    if (hdr.dp_count > 0) {
        if (!read_block(out_converter.tuya_dps.data(), hdr.dp_count * sizeof(TuyaDpIR))) return false;
    }

    out_converter.reporting_configs.resize(hdr.reporting_count);
    if (hdr.reporting_count > 0) {
        if (!read_block(out_converter.reporting_configs.data(),
                       hdr.reporting_count * sizeof(ReportingConfig))) return false;
    }

    out_converter.binds.resize(hdr.bind_count);
    if (hdr.bind_count > 0) {
        if (!read_block(out_converter.binds.data(), hdr.bind_count * sizeof(uint16_t))) return false;
    }

    return true;
}

bool ConverterMatcher::applyWhiteLabel(const DeviceInterview& interview,
                                       MatchedConverter& out_converter) {
    if (bundle_.header().version < LEGACY_V6_FORMAT_VERSION || !out_converter.matched) return false;

    const uint32_t count = bundle_.header().reserved[20] |
        (bundle_.header().reserved[21] << 8) | (bundle_.header().reserved[22] << 16) |
        (static_cast<uint32_t>(bundle_.header().reserved[23]) << 24);
    for (uint32_t i = 0; i < count; ++i) {
        WhiteLabelIR wl{};
        if (!bundle_.readWhiteLabel(i, wl)) continue;
        if (wl.record_offset != out_converter.index_entry.record_offset) continue;

        // White-label fingerprints are compared with strict equality too, and
        // their declared modelID may contain embedded NULs (for example
        // Profalux "MOT-C2Z10\0..."). getString() is length-aware on v7.
        const std::string expected_mfg = bundle_.getString(wl.fp_mfg_str_offset);
        const std::string expected_model = bundle_.getString(wl.fp_model_str_offset);
        if (!expected_mfg.empty() && expected_mfg != interview.manufacturer_name) continue;
        if (!expected_model.empty() && expected_model != interview.model_id) continue;
        if ((wl.flags & FP_FLAG_MANUFACTURER_CODE) != 0 &&
            (interview.manufacturer_code == 0 ||
             wl.manufacturer_code != interview.manufacturer_code)) continue;
        if (wl.type != 0 && wl.type != interview.logical_type) continue;
        if (wl.power_source != 0xFF && wl.power_source != interview.power_source) continue;
        if (wl.date_str_offset != 0 &&
            bundle_.getString(wl.date_str_offset) != interview.date_code) continue;
        if (wl.sw_str_offset != 0 &&
            bundle_.getString(wl.sw_str_offset) != interview.software_build_id) continue;
        if (wl.application_version >= 0 &&
            wl.application_version != interview.application_version) continue;
        if (wl.hardware_version >= 0 &&
            wl.hardware_version != interview.hardware_version) continue;
        if (wl.stack_version >= 0 &&
            wl.stack_version != interview.stack_version) continue;
        if (wl.zcl_version >= 0 &&
            wl.zcl_version != interview.zcl_version) continue;
        if ((wl.flags & FP_FLAG_IEEE_ADDR) != 0) {
            const std::string pattern = bundle_.getString(wl.ieee_str_offset);
            if (pattern.empty() || !ieeeRegexMatches(pattern, interview.ieee_addr)) continue;
        }
        if ((wl.flags & FP_FLAG_ENDPOINTS) != 0) {
            if (interview.endpoints.empty() || wl.endpoint_count == 0) continue;
            std::vector<uint16_t> expected_ids;
            expected_ids.reserve(wl.endpoint_count);
            bool endpoints_match = true;
            for (uint8_t ep_index = 0; ep_index < wl.endpoint_count; ++ep_index) {
                FingerprintEndpoint expected{};
                if (!bundle_.readFingerprintEndpoint(wl.endpoint_offset + ep_index, expected)) {
                    endpoints_match = false;
                    break;
                }
                expected_ids.push_back(expected.id);
                const EndpointInfo* actual = nullptr;
                for (const auto& ep : interview.endpoints) {
                    if (ep.ep_id == expected.id) {
                        actual = &ep;
                        break;
                    }
                }
                if (!actual) {
                    endpoints_match = false;
                    break;
                }
                if ((expected.flags & 0x01) != 0 && actual->profile_id != expected.profile_id) {
                    endpoints_match = false;
                    break;
                }
                if ((expected.flags & 0x02) != 0 && actual->device_id != expected.device_id) {
                    endpoints_match = false;
                    break;
                }
                if ((expected.flags & 0x04) != 0) {
                    std::vector<uint16_t> expected_clusters;
                    expected_clusters.reserve(expected.input_count);
                    for (uint16_t c = 0; c < expected.input_count; ++c) {
                        uint16_t cluster = 0;
                        if (!bundle_.readFingerprintCluster(expected.input_offset + c, cluster)) {
                            endpoints_match = false;
                            break;
                        }
                        expected_clusters.push_back(cluster);
                    }
                    if (!endpoints_match ||
                        !clusterListMatches(actual->input_clusters, expected_clusters)) {
                        endpoints_match = false;
                        break;
                    }
                }
                if ((expected.flags & 0x08) != 0) {
                    std::vector<uint16_t> expected_clusters;
                    expected_clusters.reserve(expected.output_count);
                    for (uint16_t c = 0; c < expected.output_count; ++c) {
                        uint16_t cluster = 0;
                        if (!bundle_.readFingerprintCluster(expected.output_offset + c, cluster)) {
                            endpoints_match = false;
                            break;
                        }
                        expected_clusters.push_back(cluster);
                    }
                    if (!endpoints_match ||
                        !clusterListMatches(actual->output_clusters, expected_clusters)) {
                        endpoints_match = false;
                        break;
                    }
                }
            }
            if (!endpoints_match || !endpointIdListMatches(interview.endpoints, expected_ids)) {
                continue;
            }
        }

        const std::string model = bundle_.getString(wl.model_str_offset);
        const std::string vendor = bundle_.getString(wl.vendor_str_offset);
        const std::string description = bundle_.getString(wl.desc_str_offset);
        if (!model.empty()) out_converter.model = model;
        if (!vendor.empty()) out_converter.vendor = vendor;
        if (!description.empty()) out_converter.description = description;
        return true;
    }
    return false;
}

bool ConverterMatcher::matchDevice(const DeviceInterview& interview, MatchedConverter& out_converter) {
    IndexEntry entry;

    // ZHC's indexer stores definitions whose fingerprint omits modelID under
    // the literal key "null" (indexer.js: addToLookup(undefined) -> "null"),
    // and getFromIndex() looks that bucket up whenever device.modelID is
    // falsy. Devices that never report a modelID (BEGA 70049, IKEA KAJPLATS)
    // are therefore resolved from the null bucket by fingerprint. Mirror the
    // substitution so they are not skipped entirely.
    const std::string lookup_model = interview.model_id.empty() ? "null" : interview.model_id;
    {
        // ZHC: a sole candidate that declares zigbeeModel is returned before
        // evaluating fingerprints.
        if (findSoleModelCandidate(lookup_model, entry)) {
            if (loadRecordDetails(entry, out_converter)) {
                applyWhiteLabel(interview, out_converter);
                out_converter.match_source = MatchSource::SOLE_MODEL;
                return true;
            }
        }

        // A sole model candidate is an authoritative official definition.
        // Do not continue into the generic capability fallback after it was
        // successfully loaded; the fallback must only run when no official
        // definition could be resolved.

        // Otherwise fingerprint wins, highest priority first; ties keep the
        // first official candidate/fingerprint order.
        if (findByFingerprint(interview.manufacturer_name, lookup_model, entry, nullptr,
                              interview.manufacturer_code, interview.date_code,
                              interview.software_build_id, interview.logical_type,
                              interview.power_source, interview.application_version,
                              interview.hardware_version, interview.stack_version,
                              interview.zcl_version, interview.ieee_addr,
                              interview.endpoints)) {
            if (loadRecordDetails(entry, out_converter)) {
                applyWhiteLabel(interview, out_converter);
                out_converter.match_source = MatchSource::EXACT_FINGERPRINT;
                return true;
            }
        }

        // Final ZHC fallback: first candidate whose zigbeeModel matches.
        if (findByModel(lookup_model, entry)) {
            if (loadRecordDetails(entry, out_converter)) {
                applyWhiteLabel(interview, out_converter);
                out_converter.match_source = MatchSource::MODEL_FALLBACK;
                return true;
            }
        }
    }

    if (interview.hasInputCluster(0x0006)) {
        out_converter.matched = true;
        out_converter.match_source = MatchSource::GENERIC_CAPABILITY;
        out_converter.model = interview.model_id.empty() ? "Generic_Switch" : interview.model_id;
        out_converter.vendor = interview.manufacturer_name;
        out_converter.category = interview.hasInputCluster(0x0008)
            ? DeviceCategory::DIMMABLE_LIGHT : DeviceCategory::ON_OFF_SWITCH;
        out_converter.category_authoritative = false;
        FromZigbeeIR fz{};
        fz.op = static_cast<uint8_t>(Opcode::READ_ATTR);
        fz.datatype = static_cast<uint8_t>(DataType::BOOL);
        fz.cluster_id = 0x0006;
        fz.attr_id = 0x0000;
        fz.scale = 1.0f;
        out_converter.fz_rules.push_back(fz);

        ToZigbeeIR tz{};
        tz.op = static_cast<uint8_t>(Opcode::COMMAND);
        tz.cluster_id = 0x0006;
        tz.cmd_or_attr = 0x02;
        tz.cmd_on = 0x01;
        tz.cmd_off = 0x00;
        out_converter.tz_rules.push_back(tz);
        return true;
    }

    return false;
}

} // namespace z2m
