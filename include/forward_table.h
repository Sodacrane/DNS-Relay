#pragma once

#include "dns_protocol.h"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <unordered_map>
#include <vector>

#include <sys/socket.h>

namespace dnsrelay {

struct ForwardItem {
    uint16_t forward_id = 0;
    uint16_t original_id = 0;
    sockaddr_storage client_addr{};
    socklen_t client_len = 0;
    std::time_t created_at = 0;
    Question question;
    std::vector<uint8_t> query;
    uint32_t retries_done = 0;
};

struct ForwardSweep {
    std::vector<ForwardItem> retries;
    std::vector<ForwardItem> expired;
};

class ForwardTable {
public:
    ForwardTable(int timeout_seconds, uint32_t max_retries);

    uint16_t add(uint16_t original_id,
                 const sockaddr_storage &client_addr,
                 socklen_t client_len,
                 const Question &question,
                 const uint8_t *query,
                 std::size_t query_len);

    bool pop(uint16_t forward_id, ForwardItem &item);
    void erase(uint16_t forward_id);
    ForwardSweep collect_due();
    std::size_t size() const;

private:
    uint16_t allocate_id();

    int timeout_seconds_ = 2;
    uint32_t max_retries_ = 1;
    uint16_t next_id_ = 0;
    std::unordered_map<uint16_t, ForwardItem> items_;
};

} // namespace dnsrelay
