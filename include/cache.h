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

// 单条缓存记录：保存完整 DNS 响应包、过期时间和 LRU 链表位置。
struct CacheEntry {
    std::vector<uint8_t> response;
    std::time_t expires_at = 0;
    std::list<std::string>::iterator lru_it;
};

struct CacheDiskEntry {
    std::time_t expires_at = 0;
    std::vector<uint8_t> response;
};

struct CacheSnapshot {
    std::string filename;
    bool persistent = false;
    std::vector<CacheDiskEntry> entries;
};

// DNS 响应缓存：缓存上游返回的完整响应包，支持 TTL 过期、容量限制和文件持久化。
class ResponseCache {
public:
    ResponseCache() = default;
    ResponseCache(std::string filename, bool persistent);
    ResponseCache(std::string filename,
                  bool persistent,
                  uint32_t min_ttl,
                  uint32_t max_ttl,
                  std::size_t capacity);

    // 启动时从缓存文件加载未过期记录，退出或更新缓存时保存到文件。
    std::size_t load();
    bool save() const;
    CacheSnapshot snapshot() const;
    static bool save_snapshot(const CacheSnapshot &snapshot);

    // 查询缓存；命中时会把响应包 ID 改成本次客户端请求的 ID。
    bool get(const Question &question,
             uint16_t response_id,
             std::vector<uint8_t> &response,
             std::time_t &ttl_left);

    // 保存上游 DNS 响应，返回最终采用的缓存 TTL；返回 0 表示不缓存。
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

    // 内部维护 LRU 顺序，并在容量超限或 TTL 到期时删除旧缓存。
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
