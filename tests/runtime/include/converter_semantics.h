#pragma once

#include "converter_types.h"
#include <algorithm>
#include <string>

namespace z2m {

// Official ZHC `ignore_*` converters are not no-ops: they consume a matching
// report and publish nothing. A converter definition may list several
// ignore_* entries for the same cluster, so the IR rule only carries the
// cluster and reports every attribute in that cluster as ignored.
constexpr uint16_t IR_ATTR_ANY = 0xFFFF;
constexpr uint16_t IR_ATTR_IGNORE = 0xFFFE;
constexpr uint8_t IR_OP_IGNORE = 0x0B;
constexpr uint8_t IR_OP_COMMAND_EVENT = 0x0C;

// Command-event kinds stored in FromZigbeeIR.datatype. The command ID is
// stored in attr_id because command and attribute namespaces are disjoint
// for this IR opcode.
constexpr uint8_t IR_COMMAND_LITERAL = 1;
constexpr uint8_t IR_COMMAND_ARM = 2;
constexpr uint8_t IR_COMMAND_MOVE_TO_LEVEL = 3;
constexpr uint8_t IR_COMMAND_MOVE = 4;
constexpr uint8_t IR_COMMAND_STEP = 5;
constexpr uint8_t IR_COMMAND_COLOR_TEMP_MOVE = 6;
constexpr uint8_t IR_COMMAND_COLOR_TEMP_STEP = 7;
constexpr uint8_t IR_COMMAND_COLOR_TEMP = 8;
constexpr uint8_t IR_COMMAND_COLOR_XY = 9;
constexpr uint8_t IR_COMMAND_ENHANCED_HUE_SAT = 10;
constexpr uint8_t IR_COMMAND_HUE_SAT = 11;
constexpr uint8_t IR_COMMAND_HUE_STEP = 12;
constexpr uint8_t IR_COMMAND_SATURATION_STEP = 13;
constexpr uint8_t IR_COMMAND_COLOR_LOOP = 14;
constexpr uint8_t IR_COMMAND_HUE_MOVE = 15;
constexpr uint8_t IR_COMMAND_SATURATION = 16;
constexpr uint8_t IR_COMMAND_HUE = 17;
constexpr uint8_t IR_COMMAND_STATE_ON = 18;
constexpr uint8_t IR_COMMAND_STATE_OFF = 19;
constexpr uint8_t IR_COMMAND_EWELINK = 20;
constexpr uint8_t IR_COMMAND_IAS_ACTION = 21;
constexpr uint8_t IR_COMMAND_IGNORE = 22;

// TuyaDpIR.datatype is a byte. Bit 7 is reserved by the v8c manifest
// envelope to mean "this DP must not be used by the incoming path". The
// low bits remain the official Tuya wire type used by toZigbee.
constexpr uint8_t TUYA_DP_FROM_UNSUPPORTED = 0x80;
constexpr uint8_t TUYA_DP_DATATYPE_MASK = 0x7F;

inline uint8_t tuyaDpDatatype(uint8_t raw) {
    return static_cast<uint8_t>(raw & TUYA_DP_DATATYPE_MASK);
}

inline bool tuyaDpFromUnsupported(uint8_t raw) {
    return (raw & TUYA_DP_FROM_UNSUPPORTED) != 0;
}

inline bool isIgnoreRule(const FromZigbeeIR& rule) {
    return rule.op == IR_OP_IGNORE;
}

inline bool isCommandEventRule(const FromZigbeeIR& rule) {
    return rule.op == IR_OP_COMMAND_EVENT;
}

inline bool isIgnoreAnyRule(const FromZigbeeIR& rule) {
    return isIgnoreRule(rule) && rule.attr_id == IR_ATTR_ANY;
}

inline bool ignoreRuleMatches(const FromZigbeeIR& rule, uint16_t cluster_id,
                              uint16_t attr_id, uint8_t endpoint_id) {
    if (!isIgnoreRule(rule) || rule.cluster_id != cluster_id) return false;
    if (rule.attr_id != IR_ATTR_ANY && rule.attr_id != attr_id) return false;
    if (rule.endpoint_id != 0 && endpoint_id != 0 &&
        rule.endpoint_id != endpoint_id) {
        return false;
    }
    return true;
}

} // namespace z2m
