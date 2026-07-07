#include "relay.h"

#include "cache.h"
#include "dns_protocol.h"
#include "forward_table.h"
#include "local_db.h"
#include "relay_handlers.h"
#include "stats_report.h"

#include "udp_socket.h"
#include "utils.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>

#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>


#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>

namespace dnsrelay {
namespace {

constexpr int FORWARD_TIMEOUT_SECONDS = 10;

volatile std::sig_atomic_t g_running = 1;

void signal_handler(int) {
    g_running = 0;
}

bool get_file_write_time(const std::string &filename,
                         std::filesystem::file_time_type &write_time,
                         std::string &error) {
    std::error_code ec;
    write_time = std::filesystem::last_write_time(filename, ec);
    if (ec) {
        error = ec.message();
        return false;
    }
    return true;
}

void reload_hosts_if_changed(const Config &cfg,
                             LocalDatabase &local_records,
                             std::optional<std::filesystem::file_time_type> &last_hosts_write,
                             std::ofstream &log) {
    std::filesystem::file_time_type current_write{};
    std::string error;
    if (!get_file_write_time(cfg.hosts_file, current_write, error)) {
        if (cfg.debug >= 1) {
            std::cerr << "[reload-skip] cannot stat " << cfg.hosts_file
                      << ": " << error << "\n";
        }
        write_log(log, "HOSTS_RELOAD_SKIP file=" + cfg.hosts_file +
                       " error=\"" + error + "\"");
        return;
    }

    if (last_hosts_write && current_write == *last_hosts_write) {
        return;
    }

    try {
        LocalDatabase reloaded = load_hosts(cfg.hosts_file);
        const std::size_t exact_count = reloaded.exact.size();
        const std::size_t wildcard_count = reloaded.wildcard.size();
        local_records = std::move(reloaded);
        last_hosts_write = current_write;

        std::cout << "[reload] hosts file " << cfg.hosts_file
                  << " reloaded, exact records " << exact_count
                  << ", wildcard records " << wildcard_count << "\n";
        write_log(log, "HOSTS_RELOAD file=" + cfg.hosts_file +
                       " exact=" + std::to_string(exact_count) +
                       " wildcard=" + std::to_string(wildcard_count));
        log_local_hosts(local_records, cfg.debug);
    } catch (const std::exception &ex) {
        if (cfg.debug >= 1) {
            std::cerr << "[reload-failed] " << cfg.hosts_file
                      << ": " << ex.what() << "\n";
        }
        write_log(log, "HOSTS_RELOAD_FAILED file=" + cfg.hosts_file +
                       " error=\"" + ex.what() + "\"");
    }
}

} // namespace

void print_stats(const Stats &stats, std::ostream &out) {
    out << "queries=" << stats.total_queries
        << " local_hits=" << stats.local_hits
        << " local_blocks=" << stats.local_blocks
        << " wildcard_hits=" << stats.wildcard_hits
        << " cache_hits=" << stats.cache_hits
        << " cache_evictions=" << stats.cache_evictions
        << " forwarded=" << stats.forwarded
        << " upstream_responses=" << stats.upstream_responses
        << " bad_queries=" << stats.bad_queries
        << " timeouts=" << stats.timeouts;
}

int run_relay(const Config &cfg) {
    g_running = 1;
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    LocalDatabase local_records;
    try {
        local_records = load_hosts(cfg.hosts_file);
    } catch (const std::exception &ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }

    std::optional<std::filesystem::file_time_type> last_hosts_write;
    std::filesystem::file_time_type initial_hosts_write{};
    std::string initial_hosts_error;
    if (get_file_write_time(cfg.hosts_file, initial_hosts_write, initial_hosts_error)) {
        last_hosts_write = initial_hosts_write;
    } else {
        std::cerr << "Warning: cannot watch hosts file " << cfg.hosts_file
                  << ": " << initial_hosts_error << "\n";
    }

    sockaddr_in upstream_addr{};
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, cfg.upstream_ip.c_str(), &upstream_addr.sin_addr) != 1) {
        std::cerr << "Invalid upstream DNS IPv4 address: " << cfg.upstream_ip << "\n";
        return 1;
    }

    std::ofstream log;
    if (cfg.logging) {
        const std::filesystem::path log_path(cfg.log_file);
        if (log_path.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(log_path.parent_path(), ec);
            if (ec) {
                std::cerr << "Warning: cannot create log directory "
                          << log_path.parent_path().string()
                          << ": " << ec.message() << "\n";
            }
        }
        log.open(cfg.log_file, std::ios::app);
        if (!log) {
            std::cerr << "Warning: cannot open log file " << cfg.log_file << ", logging disabled.\n";
        } else {
            write_log(log, "START upstream=" + cfg.upstream_ip +
                              " port=" + std::to_string(cfg.listen_port) +
                              " hosts=" + cfg.hosts_file +
                              " cache=" + (cfg.persistent_cache ? cfg.cache_file : "disabled") +
                              " cache_min_ttl=" + std::to_string(cfg.cache_min_ttl) +
                              " cache_max_ttl=" + std::to_string(cfg.cache_max_ttl) +
                              " cache_capacity=" + std::to_string(cfg.cache_capacity));
        }
    }

    int listen_sock = -1;
    int upstream_sock = -1;
    try {
        listen_sock = create_bound_socket(cfg.listen_port);
        upstream_sock = create_udp_socket();
    } catch (const std::exception &ex) {
        std::cerr << ex.what() << "\n";
        if (listen_sock >= 0) {
            close(listen_sock);
        }
        if (cfg.listen_port == 53) {
            std::cerr << "Tip: binding port 53 on WSL usually needs sudo. For quick tests use -p 1053.\n";
        }
        return 1;
    }

    std::cout << "DNS relay started on UDP port " << cfg.listen_port
              << ", upstream " << cfg.upstream_ip
              << ", hosts file " << cfg.hosts_file
              << ", exact records " << local_records.exact.size()
              << ", wildcard records " << local_records.wildcard.size()
              << ", log " << (log ? cfg.log_file : "disabled")
              << ", cache capacity " << cfg.cache_capacity
              << ", cache ttl clamp [" << cfg.cache_min_ttl
              << ", " << cfg.cache_max_ttl << "]\n";

    log_local_hosts(local_records, cfg.debug);

    ForwardTable pending(FORWARD_TIMEOUT_SECONDS);
    ResponseCache cache(cfg.cache_file,
                        cfg.persistent_cache,
                        cfg.cache_min_ttl,
                        cfg.cache_max_ttl,
                        cfg.cache_capacity);
    const std::size_t loaded_cache_entries = cache.load();
    Stats stats;
    bool stats_report_warning_printed = false;

    auto make_stats_info = [&]() {
        StatsReportInfo info;
        info.config = cfg;
        info.cache_entries = cache.size();
        info.pending_queries = pending.size();
        return info;
    };

    auto refresh_stats_report = [&]() {
        if (!write_stats_report(stats, make_stats_info()) && !stats_report_warning_printed) {
            std::cerr << "Warning: cannot write stats report " << cfg.stats_file << "\n";
            stats_report_warning_printed = true;
        }
    };

    if (cfg.persistent_cache) {
        std::cout << "Loaded " << loaded_cache_entries
                  << " unexpired cache entries from " << cfg.cache_file << "\n";
        write_log(log, "CACHE_LOAD file=" + cfg.cache_file +
                       " entries=" + std::to_string(loaded_cache_entries));
    }
    if (cfg.stats_report) {
        std::cout << "Stats dashboard: " << cfg.stats_file << "\n";
    }
    refresh_stats_report();

    auto next_hosts_reload_check = std::chrono::steady_clock::now() + std::chrono::seconds(1);

    while (g_running) {
        const auto expired = pending.cleanup_expired();
        bool stats_changed = !expired.empty();

        if (!expired.empty()) {
            stats.timeouts += expired.size();
            for (const auto &item : expired) {
                if (cfg.debug >= 1) {
                    std::cerr << "[timeout] id=" << item.forward_id << " name=" << item.qname << "\n";
                }
            }
            write_log(log, "TIMEOUT count=" + std::to_string(expired.size()));
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_sock, &readfds);
        FD_SET(upstream_sock, &readfds);

        const int max_fd = std::max(listen_sock, upstream_sock);
        timeval tv{};
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        const int ready = select(max_fd + 1, &readfds, nullptr, nullptr, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::perror("select");
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= next_hosts_reload_check) {
            reload_hosts_if_changed(cfg, local_records, last_hosts_write, log);
            next_hosts_reload_check = now + std::chrono::seconds(1);
        }

        if (ready == 0) {
            if (stats_changed) {
                refresh_stats_report();
            }
            continue;
        }

        if (FD_ISSET(listen_sock, &readfds)) {
            handle_client_packet(listen_sock,
                                 upstream_sock,
                                 upstream_addr,
                                 cfg,
                                 local_records,
                                 cache,
                                 pending,
                                 stats,
                                 log);
            stats_changed = true;

        }

        if (FD_ISSET(upstream_sock, &readfds)) {
            handle_upstream_packet(listen_sock,
                                   upstream_sock,
                                   cfg,
                                   cache,
                                   pending,
                                   stats,
                                   log);
            stats_changed = true;
        }

        if (stats_changed) {
            refresh_stats_report();

        }
    }

    std::cout << "\nDNS relay stopped.\n";
    std::cout << "Statistics: ";
    print_stats(stats, std::cout);
    std::cout << "\n";
    if (log) {
        std::ostringstream oss;
        print_stats(stats, oss);
        write_log(log, "STOP " + oss.str());
    }
    cache.save();
    refresh_stats_report();
    close(listen_sock);
    close(upstream_sock);
    return 0;
}

} // namespace dnsrelay
