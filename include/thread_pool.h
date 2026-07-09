#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace dnsrelay {

// 简单固定线程池：主线程提交任务，工作线程并发执行客户端查询处理。
class ThreadPool {
public:
    explicit ThreadPool(std::size_t thread_count);
    ~ThreadPool();

    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;

    // 提交任务、停止线程池、查询实际工作线程数量。
    void submit(std::function<void()> task);
    void shutdown();
    std::size_t thread_count() const;

private:
    // 每个工作线程循环等待任务队列，有任务就取出执行。
    void worker_loop();

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    bool stopping_ = false;
};

} // namespace dnsrelay
