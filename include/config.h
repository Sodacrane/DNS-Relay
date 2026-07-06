#pragma once

#include "dns_protocol.h"

#include <cstdint>
#include <string>

namespace dnsrelay {

struct Config {
    int debug = 0;
    std::string upstream_ip = "114.114.114.114";
    std::string hosts_file = "dnsrelay.txt";
    std::string log_file = "logs/dnsrelay.log";
    uint16_t listen_port = DNS_PORT;
    bool logging = true;
};

void print_usage(const char *program);
bool parse_args(int argc, char **argv, Config &cfg);

} // namespace dnsrelay
