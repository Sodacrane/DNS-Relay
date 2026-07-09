#pragma once

#include "dns_protocol.h"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>

namespace dnsrelay {

// 一条正在等待上游响应的转发记录：保存新 ID、原始 ID 和客户端地址。
struct ForwardItem {
    uint16_t forward_id = 0;
    uint16_t original_id = 0;
    sockaddr_storage client_addr{};
    socklen_t client_len = 0;
    std::time_t created_at = 0;
    std::string qname;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
};

// 超时记录只保留日志和统计需要的信息。
struct ForwardTimeout {
    uint16_t forward_id = 0;
    std::string qname;
};

// 转发表：把“发给上游的新 DNS ID”映射回“客户端原始请求”。
class ForwardTable {
public:
    explicit ForwardTable(int timeout_seconds);

    // 新增一条待响应请求，并分配不冲突的 forward_id。
    uint16_t add(uint16_t original_id,
                 const sockaddr_storage &client_addr,
                 socklen_t client_len,
                 const Question &question);

    // 上游响应回来时取出记录；成功后会从表中删除。
    bool pop(uint16_t forward_id, ForwardItem &item);
    void erase(uint16_t forward_id);
    std::vector<ForwardTimeout> cleanup_expired();
    std::size_t size() const;

private:
    uint16_t allocate_id();

    int timeout_seconds_ = 10;
    uint16_t next_id_ = 0;
    std::unordered_map<uint16_t, ForwardItem> items_;
};

} // namespace dnsrelay
