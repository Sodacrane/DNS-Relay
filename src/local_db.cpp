#include "local_db.h"

#include "utils.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace dnsrelay {
namespace {

// 解析 dnsrelay.txt 的一行，兼容“IP 域名”和“域名 TTL IN A/AAAA IP”两种写法。
bool parse_local_record_line(const std::vector<std::string> &fields,
                             std::string &name,
                             LocalRecord &record,
                             std::string &error) {
    if (fields.size() < 2) {
        error = "expected at least 2 fields";
        return false;
    }

    record = LocalRecord{};

    if (is_ipv4(fields[0]) || is_ipv6(fields[0])) {
        name = normalize_name(fields[1]);
        record.pattern = name;

        if (fields[0] == "0.0.0.0") {
            record.block = true;
            return true;
        }

        LocalResourceRecord rr;
        rr.type = is_ipv4(fields[0]) ? DNS_TYPE_A : DNS_TYPE_AAAA;
        rr.qclass = DNS_CLASS_IN;
        rr.ttl = DEFAULT_LOCAL_TTL;
        rr.text = fields[0];
        if (!parse_rdata(rr.type, fields[0], rr.rdata)) {
            error = "invalid address: " + fields[0];
            return false;
        }
        record.rrs.push_back(rr);
        return true;
    }

    name = normalize_name(fields[0]);
    record.pattern = name;

    std::size_t pos = 1;
    uint32_t ttl = DEFAULT_LOCAL_TTL;
    uint32_t parsed_ttl = 0;
    if (pos < fields.size() && parse_u32(fields[pos], parsed_ttl)) {
        ttl = parsed_ttl;
        ++pos;
    }

    uint16_t qclass = DNS_CLASS_IN;
    uint16_t parsed_class = 0;
    if (pos < fields.size() && parse_class(fields[pos], parsed_class)) {
        qclass = parsed_class;
        ++pos;
    }

    uint16_t type = 0;
    if (pos >= fields.size() || !parse_type(fields[pos], type)) {
        error = "expected record type A or AAAA";
        return false;
    }
    ++pos;

    if (pos >= fields.size()) {
        error = "missing record data";
        return false;
    }

    LocalResourceRecord rr;
    rr.type = type;
    rr.qclass = qclass;
    rr.ttl = ttl;
    rr.text = fields[pos];
    if (!parse_rdata(rr.type, rr.text, rr.rdata)) {
        error = "invalid " + type_to_string(rr.type) + " data: " + rr.text;
        return false;
    }

    record.rrs.push_back(rr);
    return true;
}

// 把解析出的记录放入精确表或通配符表；同名多条 A/AAAA 会合并。
void add_local_record(LocalDatabase &records, const std::string &name, const LocalRecord &record) {
    if (name.rfind("*.", 0) == 0 && name.size() > 2) {
        for (auto &wildcard : records.wildcard) {
            if (wildcard.pattern == name) {
                if (record.block) {
                    wildcard.record.block = true;
                    wildcard.record.rrs.clear();
                } else if (!wildcard.record.block) {
                    wildcard.record.rrs.insert(wildcard.record.rrs.end(), record.rrs.begin(), record.rrs.end());
                }
                return;
            }
        }
        records.wildcard.push_back(WildcardRecord{name, name.substr(1), record});
        return;
    }

    auto &slot = records.exact[name];
    if (slot.pattern.empty()) {
        slot.pattern = name;
    }
    if (record.block) {
        slot.block = true;
        slot.rrs.clear();
    } else if (!slot.block) {
        slot.rrs.insert(slot.rrs.end(), record.rrs.begin(), record.rrs.end());
    }
}

// 查询类型和 class 要匹配；ANY 查询可以匹配本地已有的任意记录。
bool rr_matches_question(const LocalResourceRecord &rr, const Question &question) {
    const bool type_match = question.qtype == DNS_TYPE_ANY || rr.type == question.qtype;
    const bool class_match = question.qclass == DNS_CLASS_ANY || rr.qclass == question.qclass;
    return type_match && class_match;
}

} // namespace

// 加载本地域名表文件，忽略空行和 # 注释，非法行会跳过并打印原因。
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

        const auto fields = split_fields(line);
        std::string name;
        LocalRecord record;
        std::string error;
        if (!parse_local_record_line(fields, name, record, error)) {
            std::cerr << "Skip invalid hosts line " << line_no << ": " << line
                      << " (" << error << ")\n";
            continue;
        }

        add_local_record(records, name, record);
    }
    return records;
}

// 先精确匹配，再按通配符后缀匹配，例如 *.demo.test。
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

// 从一条本地规则中挑出符合当前查询类型/class 的资源记录。
std::vector<const LocalResourceRecord *> matching_local_rrs(const LocalRecord &record,
                                                           const Question &question) {
    std::vector<const LocalResourceRecord *> matches;
    for (const auto &rr : record.rrs) {
        if (rr_matches_question(rr, question)) {
            matches.push_back(&rr);
        }
    }
    return matches;
}

std::string rr_to_string(const LocalResourceRecord &rr) {
    std::ostringstream oss;
    oss << type_to_string(rr.type) << " " << class_to_string(rr.qclass)
        << " TTL=" << rr.ttl << " " << rr.text;
    return oss.str();
}

} // namespace dnsrelay
