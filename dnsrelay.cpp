#include <arpa/inet.h>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
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

namespace {

constexpr std::size_t DNS_HEADER_SIZE = 12;
constexpr std::size_t MAX_DNS_PACKET = 4096;
constexpr uint16_t DNS_PORT = 53;
constexpr int FORWARD_TIMEOUT_SECONDS = 10;

volatile std::sig_atomic_t g_running = 1;

struct LocalRecord {
    in_addr address{};
    std::string pattern;
};

struct WildcardRecord {
    std::string pattern;
    std::string suffix;
    LocalRecord record{};
};

struct LocalDatabase {
    std::unordered_map<std::string, LocalRecord> exact;
    std::vector<WildcardRecord> wildcard;
};

struct Question {
    std::string qname;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    std::size_t question_end = 0;
};

struct ForwardItem {
    uint16_t original_id = 0;
    sockaddr_storage client_addr{};
    socklen_t client_len = 0;
    std::time_t created_at = 0;
    std::string qname;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
};

struct Config {
    int debug = 0;
    std::string upstream_ip = "114.114.114.114";
    std::string hosts_file = "dnsrelay.txt";
    std::string log_file = "dnsrelay.log";
    uint16_t listen_port = DNS_PORT;
    bool logging = true;
};

struct CacheEntry {
    std::vector<uint8_t> response;
    std::time_t expires_at = 0;
};

struct Stats {
    uint64_t total_queries = 0;
    uint64_t local_hits = 0;
    uint64_t local_blocks = 0;
    uint64_t wildcard_hits = 0;
    uint64_t cache_hits = 0;
    uint64_t forwarded = 0;
    uint64_t upstream_responses = 0;
    uint64_t bad_queries = 0;
    uint64_t timeouts = 0;
};

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

std::string to_lower(std::string text) {
    for (char &ch : text) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return text;
}

std::string trim(const std::string &text) {
    const char *spaces = " \t\r\n";
    const auto begin = text.find_first_not_of(spaces);
    if (begin == std::string::npos) {
        return "";
    }
    const auto end = text.find_last_not_of(spaces);
    return text.substr(begin, end - begin + 1);
}

bool ends_with(const std::string &text, const std::string &suffix) {
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string cache_key(const Question &question) {
    return question.qname + "|" + std::to_string(question.qtype) + "|" + std::to_string(question.qclass);
}

std::string cache_key(const std::string &qname, uint16_t qtype, uint16_t qclass) {
    return qname + "|" + std::to_string(qtype) + "|" + std::to_string(qclass);
}

std::string time_string() {
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void write_log(std::ofstream &log, const std::string &line) {
    if (log) {
        log << time_string() << " " << line << "\n";
        log.flush();
    }
}

std::string sockaddr_to_string(const sockaddr_storage &addr) {
    char ip[INET6_ADDRSTRLEN] = {};
    uint16_t port = 0;

    if (addr.ss_family == AF_INET) {
        const auto *a = reinterpret_cast<const sockaddr_in *>(&addr);
        inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
        port = ntohs(a->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const auto *a = reinterpret_cast<const sockaddr_in6 *>(&addr);
        inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip));
        port = ntohs(a->sin6_port);
    } else {
        return "unknown";
    }

    std::ostringstream oss;
    oss << ip << ":" << port;
    return oss.str();
}

bool is_ipv4(const std::string &text) {
    in_addr tmp{};
    return inet_pton(AF_INET, text.c_str(), &tmp) == 1;
}

bool parse_port(const std::string &text, uint16_t &port) {
    char *end = nullptr;
    long value = std::strtol(text.c_str(), &end, 10);
    if (!end || *end != '\0' || value <= 0 || value > 65535) {
        return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
}

void print_usage(const char *program) {
    std::cerr
        << "Usage: " << program << " [-d|-dd] [-p listen-port] [-l log-file] [dns-server-ipaddr] [filename]\n"
        << "Example for normal DNS port: sudo " << program << " -d 114.114.114.114 dnsrelay.txt\n"
        << "Example for WSL test port:   " << program << " -dd -p 1053 114.114.114.114 dnsrelay.txt\n";
}

bool parse_args(int argc, char **argv, Config &cfg) {
    std::vector<std::string> positional;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            std::exit(0);
        }
        if (arg == "-d") {
            cfg.debug = std::max(cfg.debug, 1);
            continue;
        }
        if (arg == "-dd") {
            cfg.debug = std::max(cfg.debug, 2);
            continue;
        }
        if (arg == "-p" || arg == "--port") {
            if (i + 1 >= argc || !parse_port(argv[++i], cfg.listen_port)) {
                std::cerr << "Invalid listen port.\n";
                return false;
            }
            continue;
        }
        if (arg == "-l" || arg == "--log") {
            if (i + 1 >= argc) {
                std::cerr << "Missing log file name.\n";
                return false;
            }
            cfg.log_file = argv[++i];
            cfg.logging = true;
            continue;
        }
        if (arg == "--no-log") {
            cfg.logging = false;
            continue;
        }
        positional.push_back(arg);
    }

    if (!positional.empty()) {
        if (is_ipv4(positional[0])) {
            cfg.upstream_ip = positional[0];
            if (positional.size() >= 2) {
                cfg.hosts_file = positional[1];
            }
            if (positional.size() > 2) {
                std::cerr << "Too many arguments.\n";
                return false;
            }
        } else {
            cfg.hosts_file = positional[0];
            if (positional.size() > 1) {
                std::cerr << "First positional argument must be an IPv4 DNS server when two arguments are used.\n";
                return false;
            }
        }
    }
    return true;
}

LocalDatabase load_hosts(const std::string &filename) {
    LocalDatabase records;
    std::ifstream in(filename);
    if (!in) {
        throw std::runtime_error("cannot open hosts file: " + filename);
    }

    std::string line;
    int line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        const auto comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        line = trim(line);
        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::string ip;
        std::string name;
        iss >> ip >> name;
        if (ip.empty() || name.empty()) {
            std::cerr << "Skip invalid hosts line " << line_no << ": " << line << "\n";
            continue;
        }

        in_addr addr{};
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
            std::cerr << "Skip invalid IPv4 address at line " << line_no << ": " << ip << "\n";
            continue;
        }

        if (!name.empty() && name.back() == '.') {
            name.pop_back();
        }
        name = to_lower(name);
        LocalRecord record{addr, name};
        if (name.rfind("*.", 0) == 0 && name.size() > 2) {
            records.wildcard.push_back(WildcardRecord{name, name.substr(1), record});
        } else {
            records.exact[name] = record;
        }
    }
    return records;
}

const LocalRecord *find_local_record(const LocalDatabase &records,
                                     const std::string &qname,
                                     bool &wildcard_match) {
    wildcard_match = false;
    const auto exact = records.exact.find(qname);
    if (exact != records.exact.end()) {
        return &exact->second;
    }

    for (const auto &record : records.wildcard) {
        const std::string root = record.suffix.size() > 1 ? record.suffix.substr(1) : "";
        if ((!root.empty() && qname == root) || ends_with(qname, record.suffix)) {
            wildcard_match = true;
            return &record.record;
        }
    }
    return nullptr;
}

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

            // OPT pseudo-RRs store extended flags in the TTL field, not a real TTL.
            if (type != 41) {
                ttl_offsets.push_back(ttl_offset);
            }
            offset += rdlength;
        }
    }
    return true;
}

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

std::vector<uint8_t> make_error_response(const uint8_t *query,
                                         std::size_t len,
                                         const Question &question,
                                         uint8_t rcode) {
    std::vector<uint8_t> response;
    const std::size_t copy_len = question.question_end <= len ? question.question_end : len;
    response.insert(response.end(), query, query + copy_len);

    const uint16_t request_flags = read_u16(query + 2);
    const uint16_t flags = static_cast<uint16_t>(
        0x8000 |                   // QR: response
        (request_flags & 0x7800) |  // OPCODE
        (request_flags & 0x0100) |  // RD
        0x0080 |                   // RA
        (rcode & 0x0f));

    set_u16(response.data() + 2, flags);
    set_u16(response.data() + 4, question.question_end > DNS_HEADER_SIZE ? 1 : 0);
    set_u16(response.data() + 6, 0);
    set_u16(response.data() + 8, 0);
    set_u16(response.data() + 10, 0);
    return response;
}

std::vector<uint8_t> make_a_response(const uint8_t *query,
                                     std::size_t len,
                                     const Question &question,
                                     in_addr address) {
    std::vector<uint8_t> response;
    response.insert(response.end(), query, query + question.question_end);

    const uint16_t request_flags = read_u16(query + 2);
    const uint16_t flags = static_cast<uint16_t>(
        0x8000 |                   // QR: response
        (request_flags & 0x7800) |  // OPCODE
        (request_flags & 0x0100) |  // RD
        0x0080);                   // RA

    set_u16(response.data() + 2, flags);
    set_u16(response.data() + 4, 1);
    set_u16(response.data() + 6, 1);
    set_u16(response.data() + 8, 0);
    set_u16(response.data() + 10, 0);

    // NAME: compression pointer to the original QNAME at offset 12.
    write_u16(response, 0xc00c);
    write_u16(response, 1);  // TYPE A
    write_u16(response, 1);  // CLASS IN
    write_u32(response, 60); // TTL
    write_u16(response, 4);  // RDLENGTH

    const auto *addr_bytes = reinterpret_cast<const uint8_t *>(&address.s_addr);
    response.insert(response.end(), addr_bytes, addr_bytes + 4);
    (void)len;
    return response;
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

void signal_handler(int) {
    g_running = 0;
}

bool is_zero_address(in_addr address) {
    return address.s_addr == htonl(0);
}

bool is_a_or_any(uint16_t qtype) {
    return qtype == 1 || qtype == 255;
}

bool is_in_or_any(uint16_t qclass) {
    return qclass == 1 || qclass == 255;
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
        std::ostringstream oss;
        oss << "bind UDP port " << port << " failed";
        throw std::runtime_error(oss.str());
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

} // namespace

int main(int argc, char **argv) {
    Config cfg;
    if (!parse_args(argc, argv, cfg)) {
        print_usage(argv[0]);
        return 1;
    }

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

    if (cfg.debug >= 2) {
        for (const auto &kv : local_records.exact) {
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &kv.second.address, ip, sizeof(ip));
            std::cerr << "[hosts] " << kv.first << " -> " << ip << "\n";
        }
        for (const auto &record : local_records.wildcard) {
            char ip[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &record.record.address, ip, sizeof(ip));
            std::cerr << "[hosts-wildcard] " << record.pattern << " -> " << ip << "\n";
        }
    }

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

            if (local_record && is_zero_address(local_record->address)) {
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

            if (local_record && is_a_or_any(question.qtype) && is_in_or_any(question.qclass)) {
                ++stats.local_hits;
                if (wildcard_match) {
                    ++stats.wildcard_hits;
                }
                auto response = make_a_response(buffer, static_cast<std::size_t>(n), question, local_record->address);
                sendto(listen_sock,
                       response.data(),
                       response.size(),
                       0,
                       reinterpret_cast<sockaddr *>(&client_addr),
                       client_len);
                if (cfg.debug >= 1) {
                    char ip[INET_ADDRSTRLEN] = {};
                    inet_ntop(AF_INET, &local_record->address, ip, sizeof(ip));
                    std::cerr << "[local-hit] " << question.qname
                              << " matched=" << local_record->pattern << " -> " << ip << "\n";
                }
                char ip[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &local_record->address, ip, sizeof(ip));
                write_log(log, "LOCAL_HIT client=" + sockaddr_to_string(client_addr) +
                               " name=" + question.qname +
                               " ip=" + ip +
                               " matched=" + local_record->pattern +
                               " wildcard=" + std::to_string(wildcard_match));
                continue;
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
