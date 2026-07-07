#pragma once

#include "config.h"
#include "relay.h"

#include <cstddef>
#include <string>

namespace dnsrelay {

struct StatsReportInfo {
    Config config;
    std::size_t cache_entries = 0;
    std::size_t pending_queries = 0;
};

bool write_stats_report(const Stats &stats, const StatsReportInfo &info);

} // namespace dnsrelay
