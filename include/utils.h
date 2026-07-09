#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <sys/socket.h>

namespace dnsrelay {

// 通用字符串、IP、端口和日志工具函数，供配置解析和 DNS 处理复用。
std::string to_lower(std::string text);
std::string trim(const std::string &text);
bool ends_with(const std::string &text, const std::string &suffix);
bool is_ipv4(const std::string &text);
bool is_ipv6(const std::string &text);
std::vector<std::string> split_fields(const std::string &line);
bool parse_u32(const std::string &text, uint32_t &value);
bool parse_port(const std::string &text, uint16_t &port);
std::string normalize_name(std::string name);
std::string time_string();
void write_log(std::ofstream &log, const std::string &line);
std::string sockaddr_to_string(const sockaddr_storage &addr);

} // namespace dnsrelay
