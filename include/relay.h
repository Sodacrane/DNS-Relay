#pragma once

#include "config.h"

#include <cstdint>
#include <iosfwd>

namespace dnsrelay {

// 运行统计信息：用于终端输出、日志和 stats/dashboard.html。
struct Stats {
    uint64_t total_queries = 0;
    uint64_t local_hits = 0;
    uint64_t local_blocks = 0;
    uint64_t wildcard_hits = 0;
    uint64_t cache_hits = 0;
    uint64_t cache_evictions = 0;
    uint64_t forwarded = 0;
    uint64_t upstream_responses = 0;
    uint64_t bad_queries = 0;
    uint64_t timeouts = 0;
};

// 主程序入口：根据 Config 启动 DNS Relay 主循环。
void print_stats(const Stats &stats, std::ostream &out);
int run_relay(const Config &cfg);

} // namespace dnsrelay
