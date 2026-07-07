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

struct ClientPacket {
    std::vector<uint8_t> data;
    sockaddr_storage client_addr{};
    socklen_t client_len = 0;
};

void log_local_hosts(const LocalDatabase &local_records, int debug);
bool receive_client_packet(int listen_sock, ClientPacket &packet);

void process_client_query(int listen_sock,
                          int upstream_sock,
                          const sockaddr_in &upstream_addr,
                          const Config &cfg,
                          SharedState &state,
                          ClientPacket packet);

void handle_upstream_packet(int listen_sock,
                            int upstream_sock,
                            const Config &cfg,
                            SharedState &state);

} // namespace dnsrelay
