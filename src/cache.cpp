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

std::string hex_encode(const std::vector<uint8_t> &data) {
    std::string encoded;
    encoded.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        encoded.push_back(hex_digit(static_cast<uint8_t>(byte >> 4)));
        encoded.push_back(hex_digit(static_cast<uint8_t>(byte & 0x0f)));
    }
    return encoded;
}

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
    : filename_(std::move(filename)), persistent_(persistent) {
}

std::size_t ResponseCache::load() {
    entries_.clear();
    if (!persistent_ || filename_.empty()) {
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
        entry.expires_at = expires_at;
        entries_[cache_key(question)] = std::move(entry);
        ++loaded;
    }

    save();
    return loaded;
}

bool ResponseCache::save() const {
    if (!persistent_ || filename_.empty()) {
        return true;
    }

    create_parent_directory(filename_);
    std::ofstream out(filename_, std::ios::trunc);
    if (!out) {
        return false;
    }

    const std::time_t now = std::time(nullptr);
    out << CACHE_MAGIC << "\n";
    for (const auto &kv : entries_) {
        if (kv.second.expires_at <= now || kv.second.response.empty()) {
            continue;
        }
        out << static_cast<long long>(kv.second.expires_at)
            << " "
            << hex_encode(kv.second.response)
            << "\n";
    }
    return true;
}

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
        save();
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
    save();
}

std::size_t ResponseCache::size() const {
    return entries_.size();
}

} // namespace dnsrelay
