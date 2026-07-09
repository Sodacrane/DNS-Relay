#include "thread_pool.h"

#include <algorithm>
#include <utility>

namespace dnsrelay {

// 固定大小线程池，至少创建 1 个工作线程，避免没有线程处理任务。
ThreadPool::ThreadPool(std::size_t thread_count) {
    const std::size_t actual_count = std::max<std::size_t>(1, thread_count);
    workers_.reserve(actual_count);
    for (std::size_t i = 0; i < actual_count; ++i) {
        workers_.emplace_back([this]() { worker_loop(); });
    }
}

ThreadPool::~ThreadPool() {
    shutdown();
}

// 主线程提交客户端查询处理任务，由空闲工作线程取走执行。
void ThreadPool::submit(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) {
            return;
        }
        tasks_.push(std::move(task));
    }
    cv_.notify_one();
}

// 通知所有工作线程退出，并等待它们 join。
void ThreadPool::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) {
            return;
        }
        stopping_ = true;
    }
    cv_.notify_all();

    for (auto &worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
}

std::size_t ThreadPool::thread_count() const {
    return workers_.size();
}

// 工作线程主循环：等待任务队列，有任务就执行；停止且无任务时退出。
void ThreadPool::worker_loop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]() {
                return stopping_ || !tasks_.empty();
            });

            if (stopping_ && tasks_.empty()) {
                return;
            }

            task = std::move(tasks_.front());
            tasks_.pop();
        }

        task();
    }
}

} // namespace dnsrelay
