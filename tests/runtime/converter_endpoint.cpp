#include "converter_endpoint.h"

namespace z2m {

uint8_t EndpointResolver::resolve(const DeviceInterview& interview,
                                  const MatchedConverter& converter,
                                  uint16_t cluster_id,
                                  uint8_t rule_endpoint) {
    // 1. If explicit endpoint provided and non-zero
    if (rule_endpoint > 0) {
        return rule_endpoint;
    }

    // 2. Search dynamically across interviewed device endpoints for the requested cluster
    if (cluster_id != 0) {
        uint8_t found_ep = interview.findEndpointForCluster(cluster_id);
        if (found_ep != 0) {
            return found_ep;
        }
    }

    // 3. Check converter's defined endpoints
    if (!converter.endpoints.empty()) {
        return converter.endpoints[0].ep_id;
    }

    // 4. Fallback to first interviewed endpoint or 1
    if (!interview.endpoints.empty()) {
        return interview.endpoints[0].ep_id;
    }

    return 1;
}

} // namespace z2m
