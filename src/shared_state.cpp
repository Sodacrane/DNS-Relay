#include "shared_state.h"

#include "utils.h"

#include <utility>

namespace dnsrelay {

// SharedState 把本地表、缓存、转发表、统计和日志集中起来，方便多模块共享。
SharedState::SharedState(LocalDatabase records, const Config &cfg, int forward_timeout_seconds)
    : local_records(std::move(records)),
      cache(cfg.cache_file,
            cfg.persistent_cache,
            cfg.cache_min_ttl,
            cfg.cache_max_ttl,
            cfg.cache_capacity),
      pending(forward_timeout_seconds) {
}

// 多线程写日志时统一加锁，避免多条日志内容交错。
void write_threadsafe_log(SharedState &state, const std::string &line) {
    std::lock_guard<std::mutex> lock(state.log_mutex);
    write_log(state.log, line);
}

// 读取统计快照时加锁，避免正在更新统计时读到中间状态。
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
