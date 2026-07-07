#include "relay_handlers.h"

#include "dns_protocol.h"
#include "utils.h"

#include <cstdio>
#include <ctime>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>

namespace dnsrelay {
namespace {

void send_client_response(int sock,
                          const std::vector<uint8_t> &response,
                          const sockaddr_storage &client_addr,
                          socklen_t client_len) {
    sendto(sock,
           response.data(),
           response.size(),
           0,
           reinterpret_cast<const sockaddr *>(&client_addr),
           client_len);
}

void add_to_stats(SharedState &state, void (*update)(Stats &)) {
    std::lock_guard<std::mutex> lock(state.stats_mutex);
    update(state.stats);
}

} // namespace

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

bool receive_client_packet(int listen_sock, ClientPacket &packet) {
    packet.data.assign(MAX_DNS_PACKET, 0);
    packet.client_addr = {};
    packet.client_len = sizeof(packet.client_addr);

    const ssize_t n = recvfrom(listen_sock,
                               packet.data.data(),
                               packet.data.size(),
                               0,
                               reinterpret_cast<sockaddr *>(&packet.client_addr),
                               &packet.client_len);
    if (n <= 0) {
        return false;
    }

    packet.data.resize(static_cast<std::size_t>(n));
    return true;
}

void process_client_query(int listen_sock,
                          int upstream_sock,
                          const sockaddr_in &upstream_addr,
                          const Config &cfg,
                          SharedState &state,
                          ClientPacket packet) {
    const uint8_t *buffer = packet.data.data();
    const std::size_t n = packet.data.size();

    Question question;
    if (!parse_question(buffer, n, question)) {
        add_to_stats(state, [](Stats &stats) { ++stats.bad_queries; });
        if (cfg.debug >= 1) {
            std::cerr << "[bad-query] from " << sockaddr_to_string(packet.client_addr)
                      << ", length=" << n << "\n";
        }
        write_threadsafe_log(state, "BAD_QUERY client=" + sockaddr_to_string(packet.client_addr) +
                                    " length=" + std::to_string(n));
        if (n >= DNS_HEADER_SIZE) {
            Question fallback;
            fallback.question_end = DNS_HEADER_SIZE;
            auto response = make_error_response(buffer, DNS_HEADER_SIZE, fallback, 1);
            send_client_response(listen_sock, response, packet.client_addr, packet.client_len);
        }
        return;
    }

    add_to_stats(state, [](Stats &stats) { ++stats.total_queries; });
    const uint16_t original_id = read_u16(buffer);

    bool wildcard_match = false;
    bool local_block = false;
    std::string matched_pattern;
    std::vector<LocalResourceRecord> local_answers;
    {
        std::shared_lock<std::shared_mutex> lock(state.local_records_mutex);
        const LocalRecord *local_record = find_local_record(state.local_records, question.qname, wildcard_match);
        if (local_record) {
            local_block = local_record->block;
            matched_pattern = local_record->pattern;
            if (!local_block) {
                const auto answer_ptrs = matching_local_rrs(*local_record, question);
                local_answers.reserve(answer_ptrs.size());
                for (const auto *rr : answer_ptrs) {
                    local_answers.push_back(*rr);
                }
            }
        }
    }

    if (cfg.debug >= 1) {
        std::cerr << "[query] id=" << original_id
                  << " from=" << sockaddr_to_string(packet.client_addr)
                  << " name=" << question.qname
                  << " type=" << question.qtype
                  << " class=" << question.qclass << "\n";
    }

    if (local_block) {
        {
            std::lock_guard<std::mutex> lock(state.stats_mutex);
            ++state.stats.local_blocks;
            if (wildcard_match) {
                ++state.stats.wildcard_hits;
            }
        }
        auto response = make_error_response(buffer, n, question, 3);
        send_client_response(listen_sock, response, packet.client_addr, packet.client_len);
        if (cfg.debug >= 1) {
            std::cerr << "[local-block] " << question.qname
                      << " matched=" << matched_pattern << " -> NXDOMAIN\n";
        }
        write_threadsafe_log(state, "LOCAL_BLOCK client=" + sockaddr_to_string(packet.client_addr) +
                                    " name=" + question.qname +
                                    " matched=" + matched_pattern +
                                    " wildcard=" + std::to_string(wildcard_match));
        return;
    }

    if (!local_answers.empty()) {
        std::vector<const LocalResourceRecord *> answer_ptrs;
        answer_ptrs.reserve(local_answers.size());
        for (const auto &rr : local_answers) {
            answer_ptrs.push_back(&rr);
        }

        {
            std::lock_guard<std::mutex> lock(state.stats_mutex);
            ++state.stats.local_hits;
            if (wildcard_match) {
                ++state.stats.wildcard_hits;
            }
        }
        auto response = make_local_response(buffer, question, answer_ptrs);
        send_client_response(listen_sock, response, packet.client_addr, packet.client_len);
        if (cfg.debug >= 1) {
            std::cerr << "[local-hit] " << question.qname
                      << " matched=" << matched_pattern
                      << " answers=" << local_answers.size()
                      << " first=" << rr_to_string(local_answers.front()) << "\n";
        }
        write_threadsafe_log(state, "LOCAL_HIT client=" + sockaddr_to_string(packet.client_addr) +
                                    " name=" + question.qname +
                                    " answers=" + std::to_string(local_answers.size()) +
                                    " first=\"" + rr_to_string(local_answers.front()) + "\"" +
                                    " matched=" + matched_pattern +
                                    " wildcard=" + std::to_string(wildcard_match));
        return;
    }

    std::vector<uint8_t> cached_response;
    std::time_t ttl_left = 0;
    bool cache_hit = false;
    {
        std::lock_guard<std::mutex> lock(state.cache_mutex);
        cache_hit = state.cache.get(question, original_id, cached_response, ttl_left);
    }
    if (cache_hit) {
        add_to_stats(state, [](Stats &stats) { ++stats.cache_hits; });
        send_client_response(listen_sock, cached_response, packet.client_addr, packet.client_len);
        if (cfg.debug >= 1) {
            std::cerr << "[cache-hit] " << question.qname
                      << " ttl-left=" << ttl_left << "s\n";
        }
        write_threadsafe_log(state, "CACHE_HIT client=" + sockaddr_to_string(packet.client_addr) +
                                    " name=" + question.qname +
                                    " key=" + cache_key(question));
        return;
    }

    std::vector<uint8_t> forward_packet(packet.data.begin(), packet.data.end());
    uint16_t forward_id = 0;
    try {
        std::lock_guard<std::mutex> lock(state.pending_mutex);
        forward_id = state.pending.add(original_id, packet.client_addr, packet.client_len, question);
    } catch (const std::exception &ex) {
        std::cerr << ex.what() << "\n";
        return;
    }
    set_u16(forward_packet.data(), forward_id);

    const ssize_t sent = sendto(upstream_sock,
                                forward_packet.data(),
                                forward_packet.size(),
                                0,
                                reinterpret_cast<const sockaddr *>(&upstream_addr),
                                sizeof(upstream_addr));
    if (sent < 0) {
        std::perror("sendto upstream");
        std::lock_guard<std::mutex> lock(state.pending_mutex);
        state.pending.erase(forward_id);
        return;
    }
    add_to_stats(state, [](Stats &stats) { ++stats.forwarded; });
    if (cfg.debug >= 1) {
        std::cerr << "[forward] client-id=" << original_id
                  << " upstream-id=" << forward_id
                  << " name=" << question.qname << "\n";
    }
    write_threadsafe_log(state, "FORWARD client=" + sockaddr_to_string(packet.client_addr) +
                                " name=" + question.qname +
                                " upstream_id=" + std::to_string(forward_id));
}

void handle_upstream_packet(int listen_sock,
                            int upstream_sock,
                            const Config &cfg,
                            SharedState &state) {
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
        return;
    }

    const uint16_t forward_id = read_u16(buffer);
    ForwardItem item;
    {
        std::lock_guard<std::mutex> lock(state.pending_mutex);
        if (!state.pending.pop(forward_id, item)) {
            if (cfg.debug >= 2) {
                std::cerr << "[drop-response] unknown upstream id=" << forward_id << "\n";
            }
            return;
        }
    }

    set_u16(buffer, item.original_id);
    add_to_stats(state, [](Stats &stats) { ++stats.upstream_responses; });

    uint32_t ttl = 0;
    uint32_t cache_ttl = 0;
    std::size_t cache_evictions = 0;
    const uint16_t rcode = read_u16(buffer + 2) & 0x000f;
    const uint16_t ancount = read_u16(buffer + 6);
    if (rcode == 0 && ancount > 0 && extract_min_answer_ttl(buffer, static_cast<std::size_t>(n), ttl)) {
        {
            std::lock_guard<std::mutex> lock(state.cache_mutex);
            const std::size_t evictions_before = state.cache.eviction_count();
            cache_ttl = state.cache.store(item.qname,
                                          item.qtype,
                                          item.qclass,
                                          buffer,
                                          static_cast<std::size_t>(n),
                                          ttl);
            cache_evictions = state.cache.eviction_count() - evictions_before;
        }
        if (cache_evictions > 0) {
            std::lock_guard<std::mutex> lock(state.stats_mutex);
            state.stats.cache_evictions += cache_evictions;
        }
        if (cache_ttl > 0 && cfg.debug >= 1) {
            std::cerr << "[cache-store] " << item.qname
                      << " upstream-ttl=" << ttl
                      << " cache-ttl=" << cache_ttl << "s\n";
        }
        if (cache_ttl > 0) {
            write_threadsafe_log(state, "CACHE_STORE name=" + item.qname +
                                        " upstream_ttl=" + std::to_string(ttl) +
                                        " cache_ttl=" + std::to_string(cache_ttl));
        } else {
            write_threadsafe_log(state, "CACHE_SKIP name=" + item.qname +
                                        " upstream_ttl=" + std::to_string(ttl));
        }
        if (cache_evictions > 0) {
            std::size_t capacity = 0;
            {
                std::lock_guard<std::mutex> lock(state.cache_mutex);
                capacity = state.cache.capacity();
            }
            write_threadsafe_log(state, "CACHE_EVICT count=" + std::to_string(cache_evictions) +
                                        " capacity=" + std::to_string(capacity));
        }
    }

    std::vector<uint8_t> client_response;
    const uint8_t *response_data = buffer;
    std::size_t response_len = static_cast<std::size_t>(n);
    if (cache_ttl > 0) {
        client_response.assign(buffer, buffer + n);
        const std::time_t expires_at = std::time(nullptr) + static_cast<std::time_t>(cache_ttl);
        if (refresh_cached_response(client_response, expires_at)) {
            response_data = client_response.data();
            response_len = client_response.size();
        }
    }

    sendto(listen_sock,
           response_data,
           response_len,
           0,
           reinterpret_cast<sockaddr *>(&item.client_addr),
           item.client_len);

    if (cfg.debug >= 1) {
        std::cerr << "[response] upstream-id=" << forward_id
                  << " client-id=" << item.original_id
                  << " name=" << item.qname
                  << " rcode=" << rcode << "\n";
    }
    write_threadsafe_log(state, "UPSTREAM_RESPONSE name=" + item.qname +
                                " upstream_id=" + std::to_string(forward_id) +
                                " rcode=" + std::to_string(rcode) +
                                " answers=" + std::to_string(ancount));
}

} // namespace dnsrelay
