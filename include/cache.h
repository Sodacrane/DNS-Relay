#pragma once

#include "dns_protocol.h"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>

namespace dnsrelay {

class ResponseCache {
public:
    bool get(const Question &question,
             uint16_t response_id,
             std::vector<uint8_t> &response,
             std::time_t &ttl_left);

    void store(const std::string &qname,
               uint16_t qtype,
               uint16_t qclass,
               const uint8_t *packet,
               std::size_t len,
               uint32_t ttl);

    std::size_t size() const;

private:
    std::unordered_map<std::string, CacheEntry> entries_;
};

} // namespace dnsrelay
