#pragma once

#include "dns_protocol.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace dnsrelay {

// 程序运行配置：由命令行参数解析得到，后续传给主循环和处理函数。
struct Config {
    int debug = 0;
    std::string upstream_ip = "114.114.114.114";
    std::string hosts_file = "dnsrelay.txt";
    std::string log_file = "logs/dnsrelay.log";
    std::string cache_file = "cache/dnsrelay.cache";
    std::string stats_file = "stats/dashboard.html";

    uint16_t listen_port = DNS_PORT;
    bool logging = true;
    bool persistent_cache = true;
    bool stats_report = true;
    uint32_t cache_min_ttl = 0;
    uint32_t cache_max_ttl = std::numeric_limits<uint32_t>::max();
    std::size_t cache_capacity = 1024;
    std::size_t thread_count = 4;
    uint32_t retry_timeout_seconds = 2;
    uint32_t max_retries = 1;
};

// 打印帮助信息，并把 argc/argv 解析到 Config。
void print_usage(const char *program);
bool parse_args(int argc, char **argv, Config &cfg);

} // namespace dnsrelay
