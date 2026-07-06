#include "cache.h"

#include <algorithm>
#include <ctime>
#include <limits>

namespace dnsrelay {

bool ResponseCache::get(const Question &question,
                        uint16_t response_id,
                        std::vector<uint8_t> &response,
                        std::time_t &ttl_left) {
    const std::string key = cache_key(question);
    auto it = entries_.find(key);
    if (it == entries_.end()) {
        return false;
    }

    response = it->second.response;
    if (!refresh_cached_response(response, it->second.expires_at)) {
        entries_.erase(it);
        return false;
    }

    set_u16(response.data(), response_id);
    ttl_left = std::max<std::time_t>(0, it->second.expires_at - std::time(nullptr));
    return true;
}

void ResponseCache::store(const std::string &qname,
                          uint16_t qtype,
                          uint16_t qclass,
                          const uint8_t *packet,
                          std::size_t len,
                          uint32_t ttl) {
    if (ttl == 0) {
        return;
    }

    CacheEntry entry;
    entry.response.assign(packet, packet + len);
    entry.expires_at = std::time(nullptr) + std::min<uint32_t>(ttl, std::numeric_limits<uint32_t>::max());
    entries_[cache_key(qname, qtype, qclass)] = entry;
}

std::size_t ResponseCache::size() const {
    return entries_.size();
}

} // namespace dnsrelay
