#include "forward_table.h"

#include <limits>
#include <stdexcept>

namespace dnsrelay {

// next_id_ 从当前时间低 16 位开始，减少程序重启后立即复用同一批 ID 的概率。
ForwardTable::ForwardTable(int timeout_seconds)
    : timeout_seconds_(timeout_seconds),
      next_id_(static_cast<uint16_t>(std::time(nullptr) & 0xffff)) {
}

// 转发前记录客户端原始 ID、客户端地址和查询信息，并分配新的上游 ID。
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

// 上游响应回来后按 forward_id 找回原请求；取出后删除，表示请求完成。
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

// 定期清理长时间没有收到上游响应的请求，避免 pending 表无限增长。
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

// 分配一个当前未使用的 16 位 DNS ID；最多尝试完整 ID 空间一圈。
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
