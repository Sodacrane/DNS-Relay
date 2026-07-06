#pragma once

#include "cache.h"
#include "config.h"
#include "forward_table.h"
#include "local_db.h"
#include "relay.h"

#include <fstream>

#include <netinet/in.h>

namespace dnsrelay {

void log_local_hosts(const LocalDatabase &local_records, int debug);

void handle_client_packet(int listen_sock,
                          int upstream_sock,
                          const sockaddr_in &upstream_addr,
                          const Config &cfg,
                          const LocalDatabase &local_records,
                          ResponseCache &cache,
                          ForwardTable &pending,
                          Stats &stats,
                          std::ofstream &log);

void handle_upstream_packet(int listen_sock,
                            int upstream_sock,
                            const Config &cfg,
                            ResponseCache &cache,
                            ForwardTable &pending,
                            Stats &stats,
                            std::ofstream &log);

} // namespace dnsrelay
