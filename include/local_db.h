#pragma once

#include "dns_protocol.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace dnsrelay {

struct LocalRecord {
    std::string pattern;
    bool block = false;
    std::vector<LocalResourceRecord> rrs;
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

LocalDatabase load_hosts(const std::string &filename);
const LocalRecord *find_local_record(const LocalDatabase &records,
                                     const std::string &qname,
                                     bool &wildcard_match);
std::vector<const LocalResourceRecord *> matching_local_rrs(const LocalRecord &record,
                                                           const Question &question);
std::string rr_to_string(const LocalResourceRecord &rr);

} // namespace dnsrelay
