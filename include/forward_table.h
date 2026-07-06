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

struct ForwardTimeout {
    uint16_t forward_id = 0;
    std::string qname;
};

class ForwardTable {
public:
    explicit ForwardTable(int timeout_seconds);

    uint16_t add(uint16_t original_id,
                 const sockaddr_storage &client_addr,
                 socklen_t client_len,
                 const Question &question);

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
