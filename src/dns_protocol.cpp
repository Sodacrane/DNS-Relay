#include "dns_protocol.h"

#include "utils.h"

#include <arpa/inet.h>

#include <algorithm>
#include <ctime>
#include <limits>
#include <sstream>

namespace dnsrelay {

// DNS 报文字段使用网络字节序，这里手动读写避免平台字节序差异。
uint16_t read_u16(const uint8_t *p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t read_u32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

void write_u16(std::vector<uint8_t> &buf, uint16_t value) {
    buf.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    buf.push_back(static_cast<uint8_t>(value & 0xff));
}

void write_u32(std::vector<uint8_t> &buf, uint32_t value) {
    buf.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    buf.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    buf.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    buf.push_back(static_cast<uint8_t>(value & 0xff));
}

void set_u16(uint8_t *p, uint16_t value) {
    p[0] = static_cast<uint8_t>((value >> 8) & 0xff);
    p[1] = static_cast<uint8_t>(value & 0xff);
}

void set_u32(uint8_t *p, uint32_t value) {
    p[0] = static_cast<uint8_t>((value >> 24) & 0xff);
    p[1] = static_cast<uint8_t>((value >> 16) & 0xff);
    p[2] = static_cast<uint8_t>((value >> 8) & 0xff);
    p[3] = static_cast<uint8_t>(value & 0xff);
}

std::string cache_key(const Question &question) {
    return question.qname + "|" + std::to_string(question.qtype) + "|" + std::to_string(question.qclass);
}

std::string cache_key(const std::string &qname, uint16_t qtype, uint16_t qclass) {
    return qname + "|" + std::to_string(qtype) + "|" + std::to_string(qclass);
}

// 将文本类型转成 DNS type 编号；本项目本地响应主要支持 A 和 AAAA。
bool parse_type(const std::string &text, uint16_t &type) {
    const std::string lower = to_lower(text);
    if (lower == "a") {
        type = DNS_TYPE_A;
        return true;
    }
    if (lower == "aaaa") {
        type = DNS_TYPE_AAAA;
        return true;
    }
    return false;
}

std::string type_to_string(uint16_t type) {
    switch (type) {
    case DNS_TYPE_A:
        return "A";
    case DNS_TYPE_AAAA:
        return "AAAA";
    default:
        return "TYPE" + std::to_string(type);
    }
}

bool parse_class(const std::string &text, uint16_t &qclass) {
    if (to_lower(text) == "in") {
        qclass = DNS_CLASS_IN;
        return true;
    }
    return false;
}

std::string class_to_string(uint16_t qclass) {
    switch (qclass) {
    case DNS_CLASS_IN:
        return "IN";
    default:
        return "CLASS" + std::to_string(qclass);
    }
}

// 把本地记录里的 IP 文本转换成 DNS RDATA 字节。
bool parse_rdata(uint16_t type, const std::string &text, std::vector<uint8_t> &rdata) {
    rdata.clear();
    if (type == DNS_TYPE_A) {
        in_addr addr{};
        if (inet_pton(AF_INET, text.c_str(), &addr) != 1) {
            return false;
        }
        const auto *bytes = reinterpret_cast<const uint8_t *>(&addr.s_addr);
        rdata.assign(bytes, bytes + 4);
        return true;
    }

    if (type == DNS_TYPE_AAAA) {
        in6_addr addr{};
        if (inet_pton(AF_INET6, text.c_str(), &addr) != 1) {
            return false;
        }
        rdata.assign(addr.s6_addr, addr.s6_addr + 16);
        return true;
    }

    return false;
}

// 解析 DNS 域名，支持普通 label 和 0xc0 开头的压缩指针。
bool decode_name(const uint8_t *packet, std::size_t len, std::size_t &offset, std::string &out) {
    std::size_t pos = offset;
    std::size_t jumped_end = 0;
    int jumps = 0;
    out.clear();

    while (true) {
        if (pos >= len) {
            return false;
        }
        const uint8_t label_len = packet[pos];

        if ((label_len & 0xc0) == 0xc0) {
            if (pos + 1 >= len) {
                return false;
            }
            const uint16_t pointer = static_cast<uint16_t>(((label_len & 0x3f) << 8) | packet[pos + 1]);
            if (pointer >= len || ++jumps > 16) {
                return false;
            }
            if (jumped_end == 0) {
                jumped_end = pos + 2;
            }
            pos = pointer;
            continue;
        }

        if ((label_len & 0xc0) != 0) {
            return false;
        }

        ++pos;
        if (label_len == 0) {
            offset = jumped_end == 0 ? pos : jumped_end;
            if (!out.empty() && out.back() == '.') {
                out.pop_back();
            }
            out = to_lower(out);
            return true;
        }

        if (pos + label_len > len) {
            return false;
        }

        if (!out.empty()) {
            out.push_back('.');
        }
        for (uint8_t i = 0; i < label_len; ++i) {
            out.push_back(static_cast<char>(packet[pos + i]));
        }
        pos += label_len;
    }
}

// 从 DNS 请求包里解析 question 区，得到域名、查询类型和 class。
bool parse_question(const uint8_t *packet, std::size_t len, Question &question) {
    if (len < DNS_HEADER_SIZE) {
        return false;
    }

    const uint16_t qdcount = read_u16(packet + 4);
    if (qdcount == 0) {
        return false;
    }

    std::size_t offset = DNS_HEADER_SIZE;
    if (!decode_name(packet, len, offset, question.qname)) {
        return false;
    }
    if (offset + 4 > len) {
        return false;
    }

    question.qtype = read_u16(packet + offset);
    question.qclass = read_u16(packet + offset + 2);
    question.question_end = offset + 4;
    return true;
}

namespace {

// 跳过一个 DNS name，用于扫描 answer/authority/additional 区。
bool skip_dns_name(const uint8_t *packet, std::size_t len, std::size_t &offset) {
    while (true) {
        if (offset >= len) {
            return false;
        }

        const uint8_t label_len = packet[offset];
        if ((label_len & 0xc0) == 0xc0) {
            if (offset + 1 >= len) {
                return false;
            }
            offset += 2;
            return true;
        }
        if ((label_len & 0xc0) != 0) {
            return false;
        }

        ++offset;
        if (label_len == 0) {
            return true;
        }
        if (offset + label_len > len) {
            return false;
        }
        offset += label_len;
    }
}

// 收集响应包中 TTL 字段的位置，后续用于取最小 TTL 或刷新缓存 TTL。
bool collect_ttl_offsets(const uint8_t *packet,
                         std::size_t len,
                         bool answers_only,
                         std::vector<std::size_t> &ttl_offsets) {
    if (len < DNS_HEADER_SIZE) {
        return false;
    }

    const uint16_t qdcount = read_u16(packet + 4);
    const uint16_t ancount = read_u16(packet + 6);
    const uint16_t nscount = answers_only ? 0 : read_u16(packet + 8);
    const uint16_t arcount = answers_only ? 0 : read_u16(packet + 10);

    std::size_t offset = DNS_HEADER_SIZE;
    for (uint16_t i = 0; i < qdcount; ++i) {
        if (!skip_dns_name(packet, len, offset) || offset + 4 > len) {
            return false;
        }
        offset += 4;
    }

    const uint16_t counts[] = {ancount, nscount, arcount};
    for (uint16_t count : counts) {
        for (uint16_t i = 0; i < count; ++i) {
            if (!skip_dns_name(packet, len, offset) || offset + 10 > len) {
                return false;
            }

            const uint16_t type = read_u16(packet + offset);
            const std::size_t ttl_offset = offset + 4;
            const uint16_t rdlength = read_u16(packet + offset + 8);
            offset += 10;
            if (offset + rdlength > len) {
                return false;
            }

            if (type != 41) {
                ttl_offsets.push_back(ttl_offset);
            }
            offset += rdlength;
        }
    }
    return true;
}

} // namespace

// 上游响应里可能有多条 answer，缓存 TTL 取最小值更保守。
bool extract_min_answer_ttl(const uint8_t *packet, std::size_t len, uint32_t &ttl) {
    std::vector<std::size_t> ttl_offsets;
    if (!collect_ttl_offsets(packet, len, true, ttl_offsets) || ttl_offsets.empty()) {
        return false;
    }

    ttl = std::numeric_limits<uint32_t>::max();
    for (std::size_t offset : ttl_offsets) {
        ttl = std::min(ttl, read_u32(packet + offset));
    }
    return ttl > 0;
}

// 缓存响应返回给客户端前，把包内 TTL 改成剩余有效时间。
bool refresh_cached_response(std::vector<uint8_t> &response, std::time_t expires_at) {
    const std::time_t now = std::time(nullptr);
    if (expires_at <= now) {
        return false;
    }

    const uint32_t remaining_ttl = static_cast<uint32_t>(
        std::min<std::time_t>(expires_at - now, std::numeric_limits<uint32_t>::max()));

    std::vector<std::size_t> ttl_offsets;
    if (!collect_ttl_offsets(response.data(), response.size(), false, ttl_offsets)) {
        return false;
    }
    for (std::size_t offset : ttl_offsets) {
        set_u32(response.data() + offset, remaining_ttl);
    }
    return true;
}

// 构造错误响应，例如本地拦截时返回 NXDOMAIN(rcode=3)。
std::vector<uint8_t> make_error_response(const uint8_t *query,
                                         std::size_t len,
                                         const Question &question,
                                         uint8_t rcode) {
    std::vector<uint8_t> response;
    const std::size_t copy_len = question.question_end <= len ? question.question_end : len;
    response.insert(response.end(), query, query + copy_len);

    const uint16_t request_flags = read_u16(query + 2);
    const uint16_t flags = static_cast<uint16_t>(
        0x8000 |
        (request_flags & 0x7800) |
        (request_flags & 0x0100) |
        0x0080 |
        (rcode & 0x0f));

    set_u16(response.data() + 2, flags);
    set_u16(response.data() + 4, question.question_end > DNS_HEADER_SIZE ? 1 : 0);
    set_u16(response.data() + 6, 0);
    set_u16(response.data() + 8, 0);
    set_u16(response.data() + 10, 0);
    return response;
}

// 构造本地命中响应；answer 名称用 0xc00c 指针复用 question 里的域名。
std::vector<uint8_t> make_local_response(const uint8_t *query,
                                         const Question &question,
                                         const std::vector<const LocalResourceRecord *> &answers) {
    std::vector<uint8_t> response;
    response.insert(response.end(), query, query + question.question_end);

    const uint16_t request_flags = read_u16(query + 2);
    const uint16_t flags = static_cast<uint16_t>(
        0x8000 |
        (request_flags & 0x7800) |
        (request_flags & 0x0100) |
        0x0080);

    set_u16(response.data() + 2, flags);
    set_u16(response.data() + 4, 1);
    set_u16(response.data() + 6, static_cast<uint16_t>(answers.size()));
    set_u16(response.data() + 8, 0);
    set_u16(response.data() + 10, 0);

    for (const auto *rr : answers) {
        write_u16(response, 0xc00c);
        write_u16(response, rr->type);
        write_u16(response, rr->qclass);
        write_u32(response, rr->ttl);
        write_u16(response, static_cast<uint16_t>(rr->rdata.size()));
        response.insert(response.end(), rr->rdata.begin(), rr->rdata.end());
    }
    return response;
}

} // namespace dnsrelay
