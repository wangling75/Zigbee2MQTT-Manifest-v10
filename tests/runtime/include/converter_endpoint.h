#pragma once

#include "converter_types.h"
#include "converter_matcher.h"

namespace z2m {

class EndpointResolver {
public:
    static uint8_t resolve(const DeviceInterview& interview,
                           const MatchedConverter& converter,
                           uint16_t cluster_id,
                           uint8_t rule_endpoint = 0);
};

} // namespace z2m
