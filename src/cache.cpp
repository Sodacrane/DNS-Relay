#include "cache.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>

namespace dnsrelay {
namespace {

constexpr const char *CACHE_MAGIC = "DNSRELAY_CACHE_V1";

// 缓存文件里把二进制 DNS 包存成十六进制文本，方便简单持久化。
char hex_digit(uint8_t value) {
    return static_cast<char>(value < 10 ? '0' + value : 'a' + (value - 10));
}

int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

// 把完整 DNS 响应包编码成十六进制字符串。
std::string hex_encode(const std::vector<uint8_t> &data) {
    std::string encoded;
    encoded.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        encoded.push_back(hex_digit(static_cast<uint8_t>(byte >> 4)));
        encoded.push_back(hex_digit(static_cast<uint8_t>(byte & 0x0f)));
    }
    return encoded;
}

// 从缓存文件恢复 DNS 响应包；格式不合法时返回 false。
bool hex_decode(const std::string &text, std::vector<uint8_t> &data) {
    if (text.size() % 2 != 0) {
        return false;
    }

    data.clear();
    data.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const int high = hex_value(text[i]);
        const int low = hex_value(text[i + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        data.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return true;
}

// 保存缓存文件前确保父目录存在，例如 cache/。
void create_parent_directory(const std::string &filename) {
    const std::filesystem::path path(filename);
    if (!path.has_parent_path()) {
        return;
    }

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
}

} // namespace

ResponseCache::ResponseCache(std::string filename, bool persistent)
    : ResponseCache(std::move(filename), persistent, 0, std::numeric_limits<uint32_t>::max(), 1024) {
}

ResponseCache::ResponseCache(std::string filename,
                             bool persistent,
                             uint32_t min_ttl,
                             uint32_t max_ttl,
                             std::size_t capacity)
    : filename_(std::move(filename)),
      persistent_(persistent),
      min_ttl_(min_ttl),
      max_ttl_(max_ttl),
      capacity_(capacity) {
}

// 启动时加载持久化缓存，只保留未过期且能解析出查询 key 的响应。
std::size_t ResponseCache::load() {
    entries_.clear();
    lru_keys_.clear();
    if (!persistent_ || filename_.empty() || capacity_ == 0) {
        return 0;
    }

    std::ifstream in(filename_);
    if (!in) {
        return 0;
    }

    std::string line;
    if (!std::getline(in, line) || line != CACHE_MAGIC) {
        return 0;
    }

    const std::time_t now = std::time(nullptr);
    std::size_t loaded = 0;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        long long expires_at_text = 0;
        std::string hex_response;
        if (!(iss >> expires_at_text >> hex_response)) {
            continue;
        }

        const std::time_t expires_at = static_cast<std::time_t>(expires_at_text);
        if (expires_at <= now) {
            continue;
        }
        const uint32_t remaining_ttl = static_cast<uint32_t>(
            std::min<std::time_t>(expires_at - now, std::numeric_limits<uint32_t>::max()));
        const uint32_t cache_ttl = clamp_ttl(remaining_ttl);
        if (cache_ttl == 0) {
            continue;
        }

        std::vector<uint8_t> response;
        if (!hex_decode(hex_response, response) || response.size() < DNS_HEADER_SIZE) {
            continue;
        }

        Question question;
        if (!parse_question(response.data(), response.size(), question)) {
            continue;
        }

        CacheEntry entry;
        entry.response = std::move(response);
        entry.expires_at = now + static_cast<std::time_t>(cache_ttl);
        insert_entry(cache_key(question), std::move(entry));
    }

    enforce_capacity();
    loaded = entries_.size();
    return loaded;
}

// 把当前未过期缓存写回文件；LRU 新记录优先写在前面。
bool ResponseCache::save() const {
    return save_snapshot(snapshot());
}

CacheSnapshot ResponseCache::snapshot() const {
    CacheSnapshot snapshot;
    snapshot.filename = filename_;
    snapshot.persistent = persistent_;
    if (!persistent_ || filename_.empty()) {
        return snapshot;
    }

    const std::time_t now = std::time(nullptr);
    for (auto lru_it = lru_keys_.rbegin(); lru_it != lru_keys_.rend(); ++lru_it) {
        const auto kv = entries_.find(*lru_it);
        if (kv == entries_.end()) {
            continue;
        }
        if (kv->second.expires_at <= now || kv->second.response.empty()) {
            continue;
        }

        CacheDiskEntry entry;
        entry.expires_at = kv->second.expires_at;
        entry.response = kv->second.response;
        snapshot.entries.push_back(std::move(entry));
    }

    return snapshot;
}

bool ResponseCache::save_snapshot(const CacheSnapshot &snapshot) {
    if (!snapshot.persistent || snapshot.filename.empty()) {
        return true;
    }

    create_parent_directory(snapshot.filename);
    std::ofstream out(snapshot.filename, std::ios::trunc);
    if (!out) {
        return false;
    }

    out << CACHE_MAGIC << "\n";
    for (const auto &entry : snapshot.entries) {
        if (entry.response.empty()) {
            continue;
        }
        out << static_cast<long long>(entry.expires_at)
            << " "
            << hex_encode(entry.response)
            << "\n";
    }
    return true;
}


// 缓存命中时刷新 TTL、改回本次请求 ID，并把该 key 移到 LRU 头部。
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
        erase_entry(it);

        return false;
    }

    touch(it);
    set_u16(response.data(), response_id);
    ttl_left = std::max<std::time_t>(0, it->second.expires_at - std::time(nullptr));
    return true;
}

// 缓存上游成功响应；TTL 会按配置的 min/max 做夹取，并触发容量淘汰。
uint32_t ResponseCache::store(const std::string &qname,
                              uint16_t qtype,
                              uint16_t qclass,
                              const uint8_t *packet,
                              std::size_t len,
                              uint32_t ttl) {
    if (ttl == 0 || capacity_ == 0) {
        return 0;
    }

    const uint32_t cache_ttl = clamp_ttl(ttl);
    if (cache_ttl == 0) {
        return 0;
    }

    prune_expired();

    CacheEntry entry;
    entry.response.assign(packet, packet + len);
    entry.expires_at = std::time(nullptr) + static_cast<std::time_t>(cache_ttl);
    insert_entry(cache_key(qname, qtype, qclass), std::move(entry));
    enforce_capacity();

    return cache_ttl;
}

std::size_t ResponseCache::size() const {
    return entries_.size();
}

std::size_t ResponseCache::capacity() const {
    return capacity_;
}

std::size_t ResponseCache::eviction_count() const {
    return evictions_;
}

// 防止缓存 TTL 过短或过长，按命令行配置限制范围。
uint32_t ResponseCache::clamp_ttl(uint32_t upstream_ttl) const {
    return std::min(std::max(upstream_ttl, min_ttl_), max_ttl_);
}

// LRU 命中后移到链表头部，表示最近使用。
void ResponseCache::touch(EntryMap::iterator it) {
    lru_keys_.splice(lru_keys_.begin(), lru_keys_, it->second.lru_it);
}

void ResponseCache::erase_entry(EntryMap::iterator it) {
    lru_keys_.erase(it->second.lru_it);
    entries_.erase(it);
}

void ResponseCache::insert_entry(const std::string &key, CacheEntry entry) {
    const auto existing = entries_.find(key);
    if (existing != entries_.end()) {
        erase_entry(existing);
    }

    lru_keys_.push_front(key);
    entry.lru_it = lru_keys_.begin();
    entries_[key] = std::move(entry);
}

// 删除已过期缓存，避免返回过期 DNS 响应。
void ResponseCache::prune_expired() {
    const std::time_t now = std::time(nullptr);
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.expires_at <= now) {
            auto erase_it = it++;
            erase_entry(erase_it);
        } else {
            ++it;
        }
    }
}

// 超过容量时从 LRU 尾部淘汰最久未使用的记录。
void ResponseCache::enforce_capacity() {
    if (capacity_ == 0) {
        entries_.clear();
        lru_keys_.clear();
        return;
    }

    while (entries_.size() > capacity_ && !lru_keys_.empty()) {
        const std::string key = lru_keys_.back();
        lru_keys_.pop_back();
        entries_.erase(key);
        ++evictions_;
    }
}

} // namespace dnsrelay
