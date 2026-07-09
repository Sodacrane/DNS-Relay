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

// 程序运行时共享状态：集中保存本地表、缓存、转发表、统计和日志。
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

// 线程安全辅助函数：写日志、快照统计、查询当前缓存和待响应请求数量。
void write_threadsafe_log(SharedState &state, const std::string &line);
Stats snapshot_stats(SharedState &state);
std::size_t cache_entry_count(SharedState &state);
std::size_t pending_query_count(SharedState &state);

} // namespace dnsrelay
