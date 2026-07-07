#pragma once

#include "cache.h"
#include "config.h"
#include "forward_table.h"
#include "local_db.h"
#include "relay.h"

#include <cstddef>
#include <fstream>
#include <mutex>
#include <shared_mutex>
#include <string>

namespace dnsrelay {

struct SharedState {
    SharedState(LocalDatabase records, const Config &cfg, int forward_timeout_seconds);

    LocalDatabase local_records;
    ResponseCache cache;
    ForwardTable pending;
    Stats stats;
    std::ofstream log;

    std::shared_mutex local_records_mutex;
    std::mutex cache_mutex;
    std::mutex pending_mutex;
    std::mutex stats_mutex;
    std::mutex log_mutex;
};

void write_threadsafe_log(SharedState &state, const std::string &line);
Stats snapshot_stats(SharedState &state);
std::size_t cache_entry_count(SharedState &state);
std::size_t pending_query_count(SharedState &state);

} // namespace dnsrelay
