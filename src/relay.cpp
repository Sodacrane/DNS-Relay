#include "relay.h"

#include "dns_protocol.h"
#include "local_db.h"
#include "utils.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace dnsrelay {
namespace {

constexpr int FORWARD_TIMEOUT_SECONDS = 10;

volatile std::sig_atomic_t g_running = 1;

struct ForwardItem {
    uint16_t original_id = 0;
    sockaddr_storage client_addr{};
    socklen_t client_len = 0;
    std::time_t created_at = 0;
    std::string qname;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
};

void signal_handler(int) {
    g_running = 0;
}

uint16_t allocate_forward_id(std::unordered_map<uint16_t, ForwardItem> &pending, uint16_t &next_id) {
    for (int i = 0; i <= std::numeric_limits<uint16_t>::max(); ++i) {
        const uint16_t candidate = next_id++;
        if (pending.find(candidate) == pending.end()) {
            return candidate;
        }
    }
    throw std::runtime_error("too many pending DNS queries");
}

std::size_t cleanup_pending(std::unordered_map<uint16_t, ForwardItem> &pending, int debug) {
    const std::time_t now = std::time(nullptr);
    std::size_t removed = 0;
    for (auto it = pending.begin(); it != pending.end();) {
        if (now - it->second.created_at > FORWARD_TIMEOUT_SECONDS) {
            if (debug >= 1) {
                std::cerr << "[timeout] id=" << it->first << " name=" << it->second.qname << "\n";
            }
            it = pending.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

int create_bound_socket(uint16_t port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("socket() failed");
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        close(sock);
        throw std::runtime_error("bind UDP port " + std::to_string(port) + " failed");
    }
    return sock;
}

int create_udp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("socket() for upstream failed");
    }
    return sock;
}

void log_local_hosts(const LocalDatabase &local_records, int debug) {
    if (debug < 2) {
        return;
    }

    for (const auto &kv : local_records.exact) {
        if (kv.second.block) {
            std::cerr << "[hosts] " << kv.first << " -> BLOCK\n";
        }
        for (const auto &rr : kv.second.rrs) {
            std::cerr << "[hosts] " << kv.first << " -> " << rr_to_string(rr) << "\n";
        }
    }
    for (const auto &record : local_records.wildcard) {
        if (record.record.block) {
            std::cerr << "[hosts-wildcard] " << record.pattern << " -> BLOCK\n";
        }
        for (const auto &rr : record.record.rrs) {
            std::cerr << "[hosts-wildcard] " << record.pattern << " -> " << rr_to_string(rr) << "\n";
        }
    }
}

} // namespace

void print_stats(const Stats &stats, std::ostream &out) {
    out << "queries=" << stats.total_queries
        << " local_hits=" << stats.local_hits
        << " local_blocks=" << stats.local_blocks
        << " wildcard_hits=" << stats.wildcard_hits
        << " cache_hits=" << stats.cache_hits
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

    sockaddr_in upstream_addr{};
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, cfg.upstream_ip.c_str(), &upstream_addr.sin_addr) != 1) {
        std::cerr << "Invalid upstream DNS IPv4 address: " << cfg.upstream_ip << "\n";
        return 1;
    }

    std::ofstream log;
    if (cfg.logging) {
        log.open(cfg.log_file, std::ios::app);
        if (!log) {
            std::cerr << "Warning: cannot open log file " << cfg.log_file << ", logging disabled.\n";
        } else {
            write_log(log, "START upstream=" + cfg.upstream_ip +
                              " port=" + std::to_string(cfg.listen_port) +
                              " hosts=" + cfg.hosts_file);
        }
    }

    int listen_sock = -1;
    int upstream_sock = -1;
    try {
        listen_sock = create_bound_socket(cfg.listen_port);
        upstream_sock = create_udp_socket();
    } catch (const std::exception &ex) {
        std::cerr << ex.what() << "\n";
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
              << ", log " << (log ? cfg.log_file : "disabled") << "\n";

    log_local_hosts(local_records, cfg.debug);

    std::unordered_map<uint16_t, ForwardItem> pending;
    std::unordered_map<std::string, CacheEntry> cache;
    Stats stats;
    uint16_t next_forward_id = static_cast<uint16_t>(std::time(nullptr) & 0xffff);

    while (g_running) {
        const std::size_t expired_pending = cleanup_pending(pending, cfg.debug);
        if (expired_pending > 0) {
            stats.timeouts += expired_pending;
            write_log(log, "TIMEOUT count=" + std::to_string(expired_pending));
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
        if (ready == 0) {
            continue;
        }

        if (FD_ISSET(listen_sock, &readfds)) {
            uint8_t buffer[MAX_DNS_PACKET] = {};
            sockaddr_storage client_addr{};
            socklen_t client_len = sizeof(client_addr);
            const ssize_t n = recvfrom(listen_sock,
                                       buffer,
                                       sizeof(buffer),
                                       0,
                                       reinterpret_cast<sockaddr *>(&client_addr),
                                       &client_len);
            if (n <= 0) {
                continue;
            }

            Question question;
            if (!parse_question(buffer, static_cast<std::size_t>(n), question)) {
                ++stats.bad_queries;
                if (cfg.debug >= 1) {
                    std::cerr << "[bad-query] from " << sockaddr_to_string(client_addr)
                              << ", length=" << n << "\n";
                }
                write_log(log, "BAD_QUERY client=" + sockaddr_to_string(client_addr) +
                               " length=" + std::to_string(n));
                if (static_cast<std::size_t>(n) >= DNS_HEADER_SIZE) {
                    Question fallback;
                    fallback.question_end = DNS_HEADER_SIZE;
                    auto response = make_error_response(buffer, DNS_HEADER_SIZE, fallback, 1);
                    sendto(listen_sock,
                           response.data(),
                           response.size(),
                           0,
                           reinterpret_cast<sockaddr *>(&client_addr),
                           client_len);
                }
                continue;
            }

            ++stats.total_queries;
            const uint16_t original_id = read_u16(buffer);
            bool wildcard_match = false;
            const LocalRecord *local_record = find_local_record(local_records, question.qname, wildcard_match);

            if (cfg.debug >= 1) {
                std::cerr << "[query] id=" << original_id
                          << " from=" << sockaddr_to_string(client_addr)
                          << " name=" << question.qname
                          << " type=" << question.qtype
                          << " class=" << question.qclass << "\n";
            }

            if (local_record && local_record->block) {
                ++stats.local_blocks;
                if (wildcard_match) {
                    ++stats.wildcard_hits;
                }
                auto response = make_error_response(buffer, static_cast<std::size_t>(n), question, 3);
                sendto(listen_sock,
                       response.data(),
                       response.size(),
                       0,
                       reinterpret_cast<sockaddr *>(&client_addr),
                       client_len);
                if (cfg.debug >= 1) {
                    std::cerr << "[local-block] " << question.qname
                              << " matched=" << local_record->pattern << " -> NXDOMAIN\n";
                }
                write_log(log, "LOCAL_BLOCK client=" + sockaddr_to_string(client_addr) +
                               " name=" + question.qname +
                               " matched=" + local_record->pattern +
                               " wildcard=" + std::to_string(wildcard_match));
                continue;
            }

            if (local_record) {
                const auto local_answers = matching_local_rrs(*local_record, question);
                if (!local_answers.empty()) {
                    ++stats.local_hits;
                    if (wildcard_match) {
                        ++stats.wildcard_hits;
                    }
                    auto response = make_local_response(buffer, question, local_answers);
                    sendto(listen_sock,
                           response.data(),
                           response.size(),
                           0,
                           reinterpret_cast<sockaddr *>(&client_addr),
                           client_len);
                    if (cfg.debug >= 1) {
                        std::cerr << "[local-hit] " << question.qname
                                  << " matched=" << local_record->pattern
                                  << " answers=" << local_answers.size()
                                  << " first=" << rr_to_string(*local_answers.front()) << "\n";
                    }
                    write_log(log, "LOCAL_HIT client=" + sockaddr_to_string(client_addr) +
                                   " name=" + question.qname +
                                   " answers=" + std::to_string(local_answers.size()) +
                                   " first=\"" + rr_to_string(*local_answers.front()) + "\"" +
                                   " matched=" + local_record->pattern +
                                   " wildcard=" + std::to_string(wildcard_match));
                    continue;
                }
            }

            const std::string key = cache_key(question);
            auto cache_it = cache.find(key);
            if (cache_it != cache.end()) {
                std::vector<uint8_t> cached_response = cache_it->second.response;
                if (refresh_cached_response(cached_response, cache_it->second.expires_at)) {
                    set_u16(cached_response.data(), original_id);
                    sendto(listen_sock,
                           cached_response.data(),
                           cached_response.size(),
                           0,
                           reinterpret_cast<sockaddr *>(&client_addr),
                           client_len);
                    ++stats.cache_hits;
                    if (cfg.debug >= 1) {
                        std::cerr << "[cache-hit] " << question.qname
                                  << " ttl-left=" << (cache_it->second.expires_at - std::time(nullptr)) << "s\n";
                    }
                    write_log(log, "CACHE_HIT client=" + sockaddr_to_string(client_addr) +
                                   " name=" + question.qname +
                                   " key=" + key);
                    continue;
                }
                cache.erase(cache_it);
            }

            std::vector<uint8_t> forward_packet(buffer, buffer + n);
            uint16_t forward_id = 0;
            try {
                forward_id = allocate_forward_id(pending, next_forward_id);
            } catch (const std::exception &ex) {
                std::cerr << ex.what() << "\n";
                continue;
            }
            set_u16(forward_packet.data(), forward_id);

            ForwardItem item;
            item.original_id = original_id;
            item.client_addr = client_addr;
            item.client_len = client_len;
            item.created_at = std::time(nullptr);
            item.qname = question.qname;
            item.qtype = question.qtype;
            item.qclass = question.qclass;
            pending[forward_id] = item;

            const ssize_t sent = sendto(upstream_sock,
                                        forward_packet.data(),
                                        forward_packet.size(),
                                        0,
                                        reinterpret_cast<sockaddr *>(&upstream_addr),
                                        sizeof(upstream_addr));
            if (sent < 0) {
                std::perror("sendto upstream");
                pending.erase(forward_id);
                continue;
            }
            ++stats.forwarded;
            if (cfg.debug >= 1) {
                std::cerr << "[forward] client-id=" << original_id
                          << " upstream-id=" << forward_id
                          << " name=" << question.qname << "\n";
            }
            write_log(log, "FORWARD client=" + sockaddr_to_string(client_addr) +
                           " name=" + question.qname +
                           " upstream_id=" + std::to_string(forward_id));
        }

        if (FD_ISSET(upstream_sock, &readfds)) {
            uint8_t buffer[MAX_DNS_PACKET] = {};
            sockaddr_storage from_addr{};
            socklen_t from_len = sizeof(from_addr);
            const ssize_t n = recvfrom(upstream_sock,
                                       buffer,
                                       sizeof(buffer),
                                       0,
                                       reinterpret_cast<sockaddr *>(&from_addr),
                                       &from_len);
            if (n <= 0 || static_cast<std::size_t>(n) < DNS_HEADER_SIZE) {
                continue;
            }

            const uint16_t forward_id = read_u16(buffer);
            auto it = pending.find(forward_id);
            if (it == pending.end()) {
                if (cfg.debug >= 2) {
                    std::cerr << "[drop-response] unknown upstream id=" << forward_id << "\n";
                }
                continue;
            }

            set_u16(buffer, it->second.original_id);
            ++stats.upstream_responses;

            uint32_t ttl = 0;
            const uint16_t rcode = read_u16(buffer + 2) & 0x000f;
            const uint16_t ancount = read_u16(buffer + 6);
            if (rcode == 0 && ancount > 0 && extract_min_answer_ttl(buffer, static_cast<std::size_t>(n), ttl)) {
                CacheEntry entry;
                entry.response.assign(buffer, buffer + n);
                entry.expires_at = std::time(nullptr) + ttl;
                cache[cache_key(it->second.qname, it->second.qtype, it->second.qclass)] = entry;
                if (cfg.debug >= 1) {
                    std::cerr << "[cache-store] " << it->second.qname
                              << " ttl=" << ttl << "s\n";
                }
                write_log(log, "CACHE_STORE name=" + it->second.qname +
                               " ttl=" + std::to_string(ttl));
            }

            sendto(listen_sock,
                   buffer,
                   static_cast<std::size_t>(n),
                   0,
                   reinterpret_cast<sockaddr *>(&it->second.client_addr),
                   it->second.client_len);

            if (cfg.debug >= 1) {
                std::cerr << "[response] upstream-id=" << forward_id
                          << " client-id=" << it->second.original_id
                          << " name=" << it->second.qname
                          << " rcode=" << rcode << "\n";
            }
            write_log(log, "UPSTREAM_RESPONSE name=" + it->second.qname +
                           " upstream_id=" + std::to_string(forward_id) +
                           " rcode=" + std::to_string(rcode) +
                           " answers=" + std::to_string(ancount));
            pending.erase(it);
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
    close(listen_sock);
    close(upstream_sock);
    return 0;
}

} // namespace dnsrelay
