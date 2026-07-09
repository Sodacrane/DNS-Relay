#pragma once

#include "dns_protocol.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace dnsrelay {

// 本地规则的一条记录：可以是拦截规则，也可以包含一个或多个 A/AAAA 记录。
struct LocalRecord {
    std::string pattern;
    bool block = false;
    std::vector<LocalResourceRecord> rrs;
};

// 通配符规则，例如 *.demo.test，会用 suffix 做后缀匹配。
struct WildcardRecord {
    std::string pattern;
    std::string suffix;
    LocalRecord record{};
};

// dnsrelay.txt 加载后的内存结构：精确匹配和通配符匹配分开存。
struct LocalDatabase {
    std::unordered_map<std::string, LocalRecord> exact;
    std::vector<WildcardRecord> wildcard;
};

// 读取本地域名表，查找匹配规则，并筛选符合查询类型的资源记录。
LocalDatabase load_hosts(const std::string &filename);
const LocalRecord *find_local_record(const LocalDatabase &records,
                                     const std::string &qname,
                                     bool &wildcard_match);
std::vector<const LocalResourceRecord *> matching_local_rrs(const LocalRecord &record,
                                                           const Question &question);
std::string rr_to_string(const LocalResourceRecord &rr);

} // namespace dnsrelay
