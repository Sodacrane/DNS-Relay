#include "shared_state.h"

#include "utils.h"

#include <utility>

namespace dnsrelay {

SharedState::SharedState(LocalDatabase records, const Config &cfg, int forward_timeout_seconds)
    : local_records(std::move(records)),
      cache(cfg.cache_file,
            cfg.persistent_cache,
            cfg.cache_min_ttl,
            cfg.cache_max_ttl,
            cfg.cache_capacity),
      pending(forward_timeout_seconds) {
}

void write_threadsafe_log(SharedState &state, const std::string &line) {
    std::lock_guard<std::mutex> lock(state.log_mutex);
    write_log(state.log, line);
}

Stats snapshot_stats(SharedState &state) {
    std::lock_guard<std::mutex> lock(state.stats_mutex);
    return state.stats;
}

std::size_t cache_entry_count(SharedState &state) {
    std::lock_guard<std::mutex> lock(state.cache_mutex);
    return state.cache.size();
}

std::size_t pending_query_count(SharedState &state) {
    std::lock_guard<std::mutex> lock(state.pending_mutex);
    return state.pending.size();
}

} // namespace dnsrelay
