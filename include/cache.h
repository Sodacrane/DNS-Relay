#pragma once

#include "dns_protocol.h"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <list>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

namespace dnsrelay {

struct CacheEntry {
    std::vector<uint8_t> response;
    std::time_t expires_at = 0;
    std::list<std::string>::iterator lru_it;
};

class ResponseCache {
public:
    ResponseCache() = default;
    ResponseCache(std::string filename, bool persistent);
    ResponseCache(std::string filename,
                  bool persistent,
                  uint32_t min_ttl,
                  uint32_t max_ttl,
                  std::size_t capacity);

    std::size_t load();
    bool save() const;


    bool get(const Question &question,
             uint16_t response_id,
             std::vector<uint8_t> &response,
             std::time_t &ttl_left);

    uint32_t store(const std::string &qname,
                   uint16_t qtype,
                   uint16_t qclass,
                   const uint8_t *packet,
                   std::size_t len,
                   uint32_t ttl);

    std::size_t size() const;
    std::size_t capacity() const;
    std::size_t eviction_count() const;

private:
    using EntryMap = std::unordered_map<std::string, CacheEntry>;

    uint32_t clamp_ttl(uint32_t upstream_ttl) const;
    void touch(EntryMap::iterator it);
    void erase_entry(EntryMap::iterator it);
    void insert_entry(const std::string &key, CacheEntry entry);
    void prune_expired();
    void enforce_capacity();

    std::string filename_;
    bool persistent_ = false;
    uint32_t min_ttl_ = 0;
    uint32_t max_ttl_ = std::numeric_limits<uint32_t>::max();
    std::size_t capacity_ = 1024;
    std::size_t evictions_ = 0;

    std::list<std::string> lru_keys_;
    EntryMap entries_;
};

} // namespace dnsrelay
