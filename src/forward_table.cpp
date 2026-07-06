#include "forward_table.h"

#include <limits>
#include <stdexcept>

namespace dnsrelay {

ForwardTable::ForwardTable(int timeout_seconds)
    : timeout_seconds_(timeout_seconds),
      next_id_(static_cast<uint16_t>(std::time(nullptr) & 0xffff)) {
}

uint16_t ForwardTable::add(uint16_t original_id,
                           const sockaddr_storage &client_addr,
                           socklen_t client_len,
                           const Question &question) {
    const uint16_t forward_id = allocate_id();

    ForwardItem item;
    item.forward_id = forward_id;
    item.original_id = original_id;
    item.client_addr = client_addr;
    item.client_len = client_len;
    item.created_at = std::time(nullptr);
    item.qname = question.qname;
    item.qtype = question.qtype;
    item.qclass = question.qclass;
    items_[forward_id] = item;

    return forward_id;
}

bool ForwardTable::pop(uint16_t forward_id, ForwardItem &item) {
    auto it = items_.find(forward_id);
    if (it == items_.end()) {
        return false;
    }

    item = it->second;
    items_.erase(it);
    return true;
}

void ForwardTable::erase(uint16_t forward_id) {
    items_.erase(forward_id);
}

std::vector<ForwardTimeout> ForwardTable::cleanup_expired() {
    const std::time_t now = std::time(nullptr);
    std::vector<ForwardTimeout> expired;

    for (auto it = items_.begin(); it != items_.end();) {
        if (now - it->second.created_at > timeout_seconds_) {
            expired.push_back({it->first, it->second.qname});
            it = items_.erase(it);
        } else {
            ++it;
        }
    }

    return expired;
}

std::size_t ForwardTable::size() const {
    return items_.size();
}

uint16_t ForwardTable::allocate_id() {
    for (int i = 0; i <= std::numeric_limits<uint16_t>::max(); ++i) {
        const uint16_t candidate = next_id_++;
        if (items_.find(candidate) == items_.end()) {
            return candidate;
        }
    }
    throw std::runtime_error("too many pending DNS queries");
}

} // namespace dnsrelay
