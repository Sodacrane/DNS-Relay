#pragma once

#include "config.h"
#include "relay.h"

#include <cstddef>
#include <string>

namespace dnsrelay {

// 生成统计页面时需要的附加信息：配置、缓存数量和待响应请求数量。
struct StatsReportInfo {
    Config config;
    std::size_t cache_entries = 0;
    std::size_t pending_queries = 0;
};

// 把当前统计数据写成 HTML 页面，默认输出到 stats/dashboard.html。
bool write_stats_report(const Stats &stats, const StatsReportInfo &info);

} // namespace dnsrelay
