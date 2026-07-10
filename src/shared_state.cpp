#include "shared_state.h"

#include "utils.h"

#include <utility>

namespace dnsrelay {
namespace {

constexpr std::size_t RECENT_EVENT_LIMIT = 12;

}

// SharedState 把本地表、缓存、转发表、统计和日志集中起来，方便多模块共享。
SharedState::SharedState(LocalDatabase records, const Config &cfg)
    : local_records(std::move(records)),
      cache(cfg.cache_file,
            cfg.persistent_cache,
            cfg.cache_min_ttl,
            cfg.cache_max_ttl,
            cfg.cache_capacity),
      pending(static_cast<int>(cfg.retry_timeout_seconds), cfg.max_retries) {
}

// 多线程写日志时统一加锁，避免多条日志内容交错。
void write_threadsafe_log(SharedState &state, const std::string &line) {
    {
        std::lock_guard<std::mutex> event_lock(state.recent_events_mutex);
        state.recent_events.push_back(line);
        while (state.recent_events.size() > RECENT_EVENT_LIMIT) {
            state.recent_events.pop_front();
        }
    }

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

std::vector<std::string> snapshot_recent_events(SharedState &state) {
    std::lock_guard<std::mutex> lock(state.recent_events_mutex);
    return std::vector<std::string>(state.recent_events.begin(), state.recent_events.end());
}

} // namespace dnsrelay
