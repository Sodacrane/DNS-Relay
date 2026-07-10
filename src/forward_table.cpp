#include "forward_table.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace dnsrelay {

ForwardTable::ForwardTable(int timeout_seconds, uint32_t max_retries)
    : timeout_seconds_(timeout_seconds),
      max_retries_(max_retries),
      next_id_(static_cast<uint16_t>(std::time(nullptr) & 0xffff)) {
}

uint16_t ForwardTable::add(uint16_t original_id,
                           const sockaddr_storage &client_addr,
                           socklen_t client_len,
                           const Question &question,
                           const uint8_t *query,
                           std::size_t query_len) {
    const uint16_t forward_id = allocate_id();

    ForwardItem item;
    item.forward_id = forward_id;
    item.original_id = original_id;
    item.client_addr = client_addr;
    item.client_len = client_len;
    item.created_at = std::time(nullptr);
    item.question = question;
    item.query.assign(query, query + query_len);
    items_[forward_id] = std::move(item);

    return forward_id;
}

bool ForwardTable::pop(uint16_t forward_id, ForwardItem &item) {
    auto it = items_.find(forward_id);
    if (it == items_.end()) {
        return false;
    }

    item = std::move(it->second);
    items_.erase(it);
    return true;
}

void ForwardTable::erase(uint16_t forward_id) {
    items_.erase(forward_id);
}

ForwardSweep ForwardTable::collect_due() {
    const std::time_t now = std::time(nullptr);
    ForwardSweep due;

    for (auto it = items_.begin(); it != items_.end();) {
        if (now - it->second.created_at < timeout_seconds_) {
            ++it;
            continue;
        }

        if (it->second.retries_done < max_retries_) {
            ++it->second.retries_done;
            it->second.created_at = now;
            due.retries.push_back(it->second);
            ++it;
        } else {
            due.expired.push_back(std::move(it->second));
            it = items_.erase(it);
        }
    }

    return due;
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
