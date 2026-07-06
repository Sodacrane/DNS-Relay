#include "utils.h"

#include <arpa/inet.h>

#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>

#include <netinet/in.h>

namespace dnsrelay {

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

bool is_ipv4(const std::string &text) {
    in_addr tmp{};
    return inet_pton(AF_INET, text.c_str(), &tmp) == 1;
}

bool is_ipv6(const std::string &text) {
    in6_addr tmp{};
    return inet_pton(AF_INET6, text.c_str(), &tmp) == 1;
}

std::vector<std::string> split_fields(const std::string &line) {
    std::istringstream iss(line);
    std::vector<std::string> fields;
    std::string field;
    while (iss >> field) {
        fields.push_back(field);
    }
    return fields;
}

bool parse_u32(const std::string &text, uint32_t &value) {
    char *end = nullptr;
    unsigned long parsed = std::strtoul(text.c_str(), &end, 10);
    if (!end || *end != '\0' || parsed > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    value = static_cast<uint32_t>(parsed);
    return true;
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

std::string normalize_name(std::string name) {
    if (!name.empty() && name.back() == '.') {
        name.pop_back();
    }
    return to_lower(name);
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

} // namespace dnsrelay
