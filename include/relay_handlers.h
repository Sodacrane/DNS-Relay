#pragma once

#include "config.h"
#include "local_db.h"
#include "shared_state.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

namespace dnsrelay {

// 从客户端 socket 收到的一整个 UDP 包，附带客户端地址，方便回包。
struct ClientPacket {
    std::vector<uint8_t> data;
    sockaddr_storage client_addr{};
    socklen_t client_len = 0;
};

// 调试用：输出当前加载的本地规则。
void log_local_hosts(const LocalDatabase &local_records, int debug);
bool receive_client_packet(int listen_sock, ClientPacket &packet);

// 处理客户端查询：本地表命中、缓存命中或转发给上游 DNS。
void process_client_query(int listen_sock,
                          int upstream_sock,
                          const sockaddr_in &upstream_addr,
                          const Config &cfg,
                          SharedState &state,
                          ClientPacket packet);

// 处理上游 DNS 响应：恢复客户端原始 ID、写缓存、回发给客户端。
void handle_upstream_packet(int listen_sock,
                            int upstream_sock,
                            const Config &cfg,
                            SharedState &state);

} // namespace dnsrelay
