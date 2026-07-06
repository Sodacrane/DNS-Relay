#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace dnsrelay {

constexpr std::size_t DNS_HEADER_SIZE = 12;
constexpr std::size_t MAX_DNS_PACKET = 4096;
constexpr uint16_t DNS_PORT = 53;
constexpr uint16_t DNS_TYPE_A = 1;
constexpr uint16_t DNS_TYPE_AAAA = 28;
constexpr uint16_t DNS_TYPE_ANY = 255;
constexpr uint16_t DNS_CLASS_IN = 1;
constexpr uint16_t DNS_CLASS_ANY = 255;
constexpr uint32_t DEFAULT_LOCAL_TTL = 60;

struct Question {
    std::string qname;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    std::size_t question_end = 0;
};

struct LocalResourceRecord {
    uint16_t type = 0;
    uint16_t qclass = DNS_CLASS_IN;
    uint32_t ttl = DEFAULT_LOCAL_TTL;
    std::vector<uint8_t> rdata;
    std::string text;
};

struct CacheEntry {
    std::vector<uint8_t> response;
    std::time_t expires_at = 0;
};

uint16_t read_u16(const uint8_t *p);
uint32_t read_u32(const uint8_t *p);
void write_u16(std::vector<uint8_t> &buf, uint16_t value);
void write_u32(std::vector<uint8_t> &buf, uint32_t value);
void set_u16(uint8_t *p, uint16_t value);
void set_u32(uint8_t *p, uint32_t value);

std::string cache_key(const Question &question);
std::string cache_key(const std::string &qname, uint16_t qtype, uint16_t qclass);

bool parse_type(const std::string &text, uint16_t &type);
std::string type_to_string(uint16_t type);
bool parse_class(const std::string &text, uint16_t &qclass);
std::string class_to_string(uint16_t qclass);
bool parse_rdata(uint16_t type, const std::string &text, std::vector<uint8_t> &rdata);

bool decode_name(const uint8_t *packet, std::size_t len, std::size_t &offset, std::string &out);
bool parse_question(const uint8_t *packet, std::size_t len, Question &question);

bool extract_min_answer_ttl(const uint8_t *packet, std::size_t len, uint32_t &ttl);
bool refresh_cached_response(std::vector<uint8_t> &response, std::time_t expires_at);

std::vector<uint8_t> make_error_response(const uint8_t *query,
                                         std::size_t len,
                                         const Question &question,
                                         uint8_t rcode);
std::vector<uint8_t> make_local_response(const uint8_t *query,
                                         const Question &question,
                                         const std::vector<const LocalResourceRecord *> &answers);

} // namespace dnsrelay
