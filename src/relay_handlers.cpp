#include "relay_handlers.h"

#include "dns_protocol.h"
#include "utils.h"

#include <cstdio>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <string>
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

void handle_client_packet(int listen_sock,
                          int upstream_sock,
                          const sockaddr_in &upstream_addr,
                          const Config &cfg,
                          const LocalDatabase &local_records,
                          ResponseCache &cache,
                          ForwardTable &pending,
                          Stats &stats,
                          std::ofstream &log) {
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
        return;
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
            send_client_response(listen_sock, response, client_addr, client_len);
        }
        return;
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
        send_client_response(listen_sock, response, client_addr, client_len);
        if (cfg.debug >= 1) {
            std::cerr << "[local-block] " << question.qname
                      << " matched=" << local_record->pattern << " -> NXDOMAIN\n";
        }
        write_log(log, "LOCAL_BLOCK client=" + sockaddr_to_string(client_addr) +
                       " name=" + question.qname +
                       " matched=" + local_record->pattern +
                       " wildcard=" + std::to_string(wildcard_match));
        return;
    }

    if (local_record) {
        const auto local_answers = matching_local_rrs(*local_record, question);
        if (!local_answers.empty()) {
            ++stats.local_hits;
            if (wildcard_match) {
                ++stats.wildcard_hits;
            }
            auto response = make_local_response(buffer, question, local_answers);
            send_client_response(listen_sock, response, client_addr, client_len);
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
            return;
        }
    }

    std::vector<uint8_t> cached_response;
    std::time_t ttl_left = 0;
    if (cache.get(question, original_id, cached_response, ttl_left)) {
        send_client_response(listen_sock, cached_response, client_addr, client_len);
        ++stats.cache_hits;
        if (cfg.debug >= 1) {
            std::cerr << "[cache-hit] " << question.qname
                      << " ttl-left=" << ttl_left << "s\n";
        }
        write_log(log, "CACHE_HIT client=" + sockaddr_to_string(client_addr) +
                       " name=" + question.qname +
                       " key=" + cache_key(question));
        return;
    }

    std::vector<uint8_t> forward_packet(buffer, buffer + n);
    uint16_t forward_id = 0;
    try {
        forward_id = pending.add(original_id, client_addr, client_len, question);
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
        pending.erase(forward_id);
        return;
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

void handle_upstream_packet(int listen_sock,
                            int upstream_sock,
                            const Config &cfg,
                            ResponseCache &cache,
                            ForwardTable &pending,
                            Stats &stats,
                            std::ofstream &log) {
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
    if (!pending.pop(forward_id, item)) {
        if (cfg.debug >= 2) {
            std::cerr << "[drop-response] unknown upstream id=" << forward_id << "\n";
        }
        return;
    }

    set_u16(buffer, item.original_id);
    ++stats.upstream_responses;

    uint32_t ttl = 0;
    const uint16_t rcode = read_u16(buffer + 2) & 0x000f;
    const uint16_t ancount = read_u16(buffer + 6);
    if (rcode == 0 && ancount > 0 && extract_min_answer_ttl(buffer, static_cast<std::size_t>(n), ttl)) {
        cache.store(item.qname, item.qtype, item.qclass, buffer, static_cast<std::size_t>(n), ttl);
        if (cfg.debug >= 1) {
            std::cerr << "[cache-store] " << item.qname
                      << " ttl=" << ttl << "s\n";
        }
        write_log(log, "CACHE_STORE name=" + item.qname +
                       " ttl=" + std::to_string(ttl));
    }

    sendto(listen_sock,
           buffer,
           static_cast<std::size_t>(n),
           0,
           reinterpret_cast<sockaddr *>(&item.client_addr),
           item.client_len);

    if (cfg.debug >= 1) {
        std::cerr << "[response] upstream-id=" << forward_id
                  << " client-id=" << item.original_id
                  << " name=" << item.qname
                  << " rcode=" << rcode << "\n";
    }
    write_log(log, "UPSTREAM_RESPONSE name=" + item.qname +
                   " upstream_id=" + std::to_string(forward_id) +
                   " rcode=" + std::to_string(rcode) +
                   " answers=" + std::to_string(ancount));
}

} // namespace dnsrelay
