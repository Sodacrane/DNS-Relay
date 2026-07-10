#include "stats_report.h"

#include "utils.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

namespace dnsrelay {
namespace {

struct Metric {
    std::string label;
    uint64_t value = 0;
    std::string accent;
    std::string note;
};

std::string html_escape(const std::string &text) {
    std::string out;
    out.reserve(text.size());
    for (char ch : text) {
        switch (ch) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        default:
            out.push_back(ch);
            break;
        }
    }
    return out;
}

std::string percent(uint64_t value, uint64_t total) {
    if (total == 0) {
        return "0.0%";
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1)
        << (static_cast<double>(value) * 100.0 / static_cast<double>(total))
        << "%";
    return oss.str();
}

void ensure_parent_directory(const std::string &filename) {
    const std::filesystem::path path(filename);
    if (!path.has_parent_path()) {
        return;
    }

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
}

void write_metric_tile(std::ostream &out, const Metric &metric) {
    out << "<section class=\"metric\" style=\"--accent:" << metric.accent << "\">"
        << "<div class=\"metric-label\">" << html_escape(metric.label) << "</div>"
        << "<div class=\"metric-value\">" << metric.value << "</div>"
        << "<div class=\"metric-note\">" << html_escape(metric.note) << "</div>"
        << "</section>\n";
}

void write_stat_row(std::ostream &out,
                    const std::string &label,
                    uint64_t value,
                    const std::string &accent) {
    out << "<div class=\"stat-row\" style=\"--accent:" << accent << "\">"
        << "<span>" << html_escape(label) << "</span>"
        << "<strong>" << value << "</strong>"
        << "</div>\n";
}

void write_bar(std::ostream &out, const Metric &metric, uint64_t max_value) {
    const double width = max_value == 0 ? 0.0 :
        (static_cast<double>(metric.value) * 100.0 / static_cast<double>(max_value));

    out << "<div class=\"bar-row\">"
        << "<div class=\"bar-name\">" << html_escape(metric.label) << "</div>"
        << "<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:"
        << std::fixed << std::setprecision(1) << width << "%;background:"
        << metric.accent << "\"></div></div>"
        << "<div class=\"bar-count\">" << metric.value << "</div>"
        << "</div>\n";
}

} // namespace

bool write_stats_report(const Stats &stats, const StatsReportInfo &info) {
    if (!info.config.stats_report || info.config.stats_file.empty()) {
        return true;
    }

    ensure_parent_directory(info.config.stats_file);
    std::ofstream out(info.config.stats_file, std::ios::trunc);
    if (!out) {
        return false;
    }

    const uint64_t total = std::max<uint64_t>(stats.total_queries, 1);
    const uint64_t local_rule_hits = stats.local_hits + stats.local_blocks;
    const uint64_t answered_without_upstream = local_rule_hits + stats.cache_hits;
    const uint64_t relay_responses = answered_without_upstream +
                                     stats.upstream_responses +
                                     stats.servfail_responses;
    const uint64_t upstream_attempts = stats.forwarded + stats.retries;

    const std::vector<Metric> distribution = {
        {"Local hits", stats.local_hits, "#2f8f5b", percent(stats.local_hits, total)},
        {"Local blocks", stats.local_blocks, "#c2410c", percent(stats.local_blocks, total)},
        {"Wildcard hits", stats.wildcard_hits, "#7c3aed", percent(stats.wildcard_hits, total)},
        {"Cache hits", stats.cache_hits, "#2563eb", percent(stats.cache_hits, total)},
        {"Forwarded", stats.forwarded, "#b7791f", percent(stats.forwarded, total)},
        {"Upstream responses", stats.upstream_responses, "#0f766e", percent(stats.upstream_responses, total)},
        {"Retries", stats.retries, "#d97706", percent(stats.retries, total)},
        {"Timeouts", stats.timeouts, "#64748b", percent(stats.timeouts, total)},
        {"SERVFAIL", stats.servfail_responses, "#b91c1c", percent(stats.servfail_responses, total)},
        {"Bad queries", stats.bad_queries, "#991b1b", percent(stats.bad_queries, total)},
        {"Cache evictions", stats.cache_evictions, "#475569", "LRU"}
    };

    uint64_t max_value = 1;
    for (const auto &metric : distribution) {
        max_value = std::max(max_value, metric.value);
    }

    out << "<!doctype html>\n"
        << "<html lang=\"en\">\n"
        << "<head>\n"
        << "<meta charset=\"utf-8\">\n"
        << "<meta http-equiv=\"refresh\" content=\"2\">\n"
        << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        << "<title>DNS Relay Monitor</title>\n"
        << "<style>\n"
        << ":root{color-scheme:light;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f5f7fb;color:#172033;}\n"
        << "*{box-sizing:border-box}body{margin:0;padding:22px;background:#f5f7fb;}\n"
        << "main{max-width:1180px;margin:0 auto;display:grid;gap:14px;}\n"
        << "header{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;padding-bottom:14px;border-bottom:1px solid #d8dee8;}\n"
        << "h1{font-size:27px;line-height:1.12;margin:0;color:#101828;font-weight:760;letter-spacing:0;}\n"
        << ".subtitle{margin-top:6px;color:#667085;font-size:13px;}\n"
        << ".header-side{display:flex;align-items:center;gap:12px;flex-wrap:wrap;justify-content:flex-end;}\n"
        << ".status-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid #b7e4c7;background:#e9f8ee;color:#17623a;border-radius:999px;padding:7px 11px;font-size:12px;font-weight:760;}\n"
        << ".dot{width:8px;height:8px;border-radius:50%;background:#22a45a;box-shadow:0 0 0 4px rgba(34,164,90,.12);}\n"
        << ".updated{font-size:12px;color:#667085;text-align:right;}\n"
        << ".status-strip{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;}\n"
        << ".status-item{background:#fff;border:1px solid #dde3ec;border-radius:8px;padding:11px 12px;min-width:0;}\n"
        << ".status-item span{display:block;color:#667085;font-size:12px;font-weight:680;}\n"
        << ".status-item strong{display:block;margin-top:7px;color:#172033;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}\n"
        << ".metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;}\n"
        << ".metric{background:#fff;border:1px solid #dde3ec;border-left:5px solid var(--accent);border-radius:8px;padding:14px;min-height:112px;}\n"
        << ".metric-label{font-size:13px;color:#596579;font-weight:700;}\n"
        << ".metric-value{font-size:31px;font-weight:780;color:#101828;margin-top:12px;font-variant-numeric:tabular-nums;}\n"
        << ".metric-note{font-size:12px;color:#667085;margin-top:8px;min-height:16px;}\n"
        << ".panel{background:#fff;border:1px solid #dde3ec;border-radius:8px;padding:16px;}\n"
        << "h2{font-size:16px;margin:0 0 14px;color:#172033;letter-spacing:0;}\n"
        << ".flow-path{display:grid;grid-template-columns:1fr 34px 1.05fr 34px 1fr 34px 1fr;align-items:center;gap:8px;}\n"
        << ".flow-node{border-radius:8px;padding:13px 14px;background:#f8fafc;min-height:88px;border-top:4px solid var(--accent);}\n"
        << ".flow-node span{display:block;color:#667085;font-size:12px;font-weight:700;}\n"
        << ".flow-node strong{display:block;color:#101828;font-size:25px;margin-top:9px;font-variant-numeric:tabular-nums;}\n"
        << ".flow-node em{display:block;color:#667085;font-size:12px;font-style:normal;margin-top:3px;}\n"
        << ".arrow{height:2px;background:#cbd5e1;position:relative;}\n"
        << ".arrow:after{content:\"\";position:absolute;right:-1px;top:-4px;border-left:8px solid #cbd5e1;border-top:5px solid transparent;border-bottom:5px solid transparent;}\n"
        << ".flow-detail{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:12px;}\n"
        << ".detail-unit{border-top:1px solid #e3e8ef;padding-top:10px;display:flex;justify-content:space-between;gap:10px;color:#445066;font-size:13px;}\n"
        << ".detail-unit strong{color:#172033;font-variant-numeric:tabular-nums;}\n"
        << ".main-grid{display:grid;grid-template-columns:1.25fr .75fr;gap:14px;align-items:start;}\n"
        << ".group-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;}\n"
        << ".stat-group{border-top:3px solid #d8dee8;padding-top:10px;}\n"
        << ".stat-group h3{font-size:13px;margin:0 0 8px;color:#475467;letter-spacing:0;text-transform:uppercase;}\n"
        << ".stat-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid #edf1f6;}\n"
        << ".stat-row span{font-size:13px;color:#445066;}.stat-row strong{font-size:15px;color:var(--accent);font-variant-numeric:tabular-nums;}\n"
        << ".bar-row{display:grid;grid-template-columns:150px 1fr 70px;gap:12px;align-items:center;margin:11px 0;}\n"
        << ".bar-name{font-size:13px;color:#384153;font-weight:650;}.bar-track{height:13px;background:#e9edf4;border-radius:999px;overflow:hidden;}\n"
        << ".bar-fill{height:100%;min-width:0;border-radius:999px;}.bar-count{text-align:right;font-variant-numeric:tabular-nums;color:#172033;font-weight:720;}\n"
        << ".kv{display:grid;grid-template-columns:118px 1fr;gap:8px 12px;font-size:13px;}\n"
        << ".kv dt{color:#667085;font-weight:700;}.kv dd{margin:0;color:#172033;word-break:break-word;}\n"
        << "@media(max-width:960px){body{padding:14px}.status-strip,.metrics,.main-grid,.group-grid,.flow-detail{grid-template-columns:1fr}.flow-path{grid-template-columns:1fr;}.arrow{height:24px;width:2px;margin:auto}.arrow:after{right:-4px;top:18px;border-left:5px solid transparent;border-right:5px solid transparent;border-top:8px solid #cbd5e1;border-bottom:0}.bar-row{grid-template-columns:116px 1fr 48px}header{align-items:flex-start;flex-direction:column}.header-side{justify-content:flex-start}.updated{text-align:left}}\n"
        << "</style>\n"
        << "</head>\n"
        << "<body>\n"
        << "<main>\n"
        << "<header><div><h1>DNS Relay Monitor</h1><div class=\"subtitle\">"
        << html_escape(info.config.hosts_file) << " -> " << html_escape(info.config.upstream_ip)
        << "</div></div><div class=\"header-side\"><div class=\"status-pill\"><span class=\"dot\"></span>RUNNING</div>"
        << "<div class=\"updated\">Updated " << html_escape(time_string()) << "<br>Refresh 2s</div></div></header>\n";

    out << "<section class=\"status-strip\">\n"
        << "<div class=\"status-item\"><span>Listen port</span><strong>" << info.config.listen_port << "</strong></div>\n"
        << "<div class=\"status-item\"><span>Upstream DNS</span><strong>" << html_escape(info.config.upstream_ip) << "</strong></div>\n"
        << "<div class=\"status-item\"><span>Worker threads</span><strong>" << info.config.thread_count << "</strong></div>\n"
        << "<div class=\"status-item\"><span>Cache entries</span><strong>" << info.cache_entries << " / " << info.config.cache_capacity << "</strong></div>\n"
        << "<div class=\"status-item\"><span>Pending queries</span><strong>" << info.pending_queries << "</strong></div>\n"
        << "</section>\n";

    out << "<section class=\"metrics\">\n";
    write_metric_tile(out, {"Total queries", stats.total_queries, "#111827", "all received DNS requests"});
    write_metric_tile(out, {"Answered by relay", relay_responses, "#2f8f5b", percent(relay_responses, total) + " of queries"});
    write_metric_tile(out, {"Forwarded", stats.forwarded, "#b7791f", "sent to upstream DNS"});
    write_metric_tile(out, {"Cache hits", stats.cache_hits, "#2563eb", percent(stats.cache_hits, total) + " hit rate"});
    out << "</section>\n";

    out << "<section class=\"panel\"><h2>Resolution Path</h2>"
        << "<div class=\"flow-path\">"
        << "<div class=\"flow-node\" style=\"--accent:#111827\"><span>Client</span><strong>" << stats.total_queries << "</strong><em>queries in</em></div>"
        << "<div class=\"arrow\"></div>"
        << "<div class=\"flow-node\" style=\"--accent:#2563eb\"><span>DNS Relay</span><strong>" << answered_without_upstream << "</strong><em>local/cache answers</em></div>"
        << "<div class=\"arrow\"></div>"
        << "<div class=\"flow-node\" style=\"--accent:#b7791f\"><span>Upstream DNS</span><strong>" << upstream_attempts << "</strong><em>forward + retry</em></div>"
        << "<div class=\"arrow\"></div>"
        << "<div class=\"flow-node\" style=\"--accent:#2f8f5b\"><span>Response</span><strong>" << relay_responses << "</strong><em>answers out</em></div>"
        << "</div>"
        << "<div class=\"flow-detail\">"
        << "<div class=\"detail-unit\"><span>Local rules</span><strong>" << local_rule_hits << "</strong></div>"
        << "<div class=\"detail-unit\"><span>Cache hits</span><strong>" << stats.cache_hits << "</strong></div>"
        << "<div class=\"detail-unit\"><span>Upstream success</span><strong>" << stats.upstream_responses << "</strong></div>"
        << "</div></section>\n";

    out << "<section class=\"main-grid\">\n"
        << "<div class=\"panel\"><h2>Grouped Metrics</h2><div class=\"group-grid\">\n"
        << "<section class=\"stat-group\"><h3>Requests</h3>";
    write_stat_row(out, "Total queries", stats.total_queries, "#111827");
    write_stat_row(out, "Forwarded", stats.forwarded, "#b7791f");
    write_stat_row(out, "Bad queries", stats.bad_queries, "#991b1b");
    out << "</section><section class=\"stat-group\"><h3>Rules</h3>";
    write_stat_row(out, "Local hits", stats.local_hits, "#2f8f5b");
    write_stat_row(out, "Local blocks", stats.local_blocks, "#c2410c");
    write_stat_row(out, "Wildcard hits", stats.wildcard_hits, "#7c3aed");
    out << "</section><section class=\"stat-group\"><h3>Upstream</h3>";
    write_stat_row(out, "Responses", stats.upstream_responses, "#0f766e");
    write_stat_row(out, "Retries", stats.retries, "#d97706");
    write_stat_row(out, "SERVFAIL", stats.servfail_responses, "#b91c1c");
    out << "</section><section class=\"stat-group\"><h3>Cache</h3>";
    write_stat_row(out, "Hits", stats.cache_hits, "#2563eb");
    write_stat_row(out, "Entries", info.cache_entries, "#2563eb");
    write_stat_row(out, "Evictions", stats.cache_evictions, "#475569");
    out << "</section></div></div>\n";

    out << "<aside class=\"panel\"><h2>Runtime</h2><dl class=\"kv\">"
        << "<dt>Threads</dt><dd>" << info.config.thread_count << "</dd>"
        << "<dt>Retry policy</dt><dd>" << info.config.max_retries
        << " retries, " << info.config.retry_timeout_seconds << "s timeout</dd>"
        << "<dt>Hosts file</dt><dd>" << html_escape(info.config.hosts_file) << "</dd>"
        << "<dt>Log file</dt><dd>" << (info.config.logging ? html_escape(info.config.log_file) : "disabled") << "</dd>"
        << "<dt>Cache file</dt><dd>" << (info.config.persistent_cache ? html_escape(info.config.cache_file) : "disabled") << "</dd>"
        << "<dt>TTL clamp</dt><dd>" << info.config.cache_min_ttl << " - " << info.config.cache_max_ttl << " seconds</dd>"
        << "<dt>Upstream rate</dt><dd>" << percent(stats.upstream_responses, std::max<uint64_t>(stats.forwarded, 1)) << "</dd>"
        << "</dl></aside>\n"
        << "</section>\n";

    out << "<section class=\"panel\"><h2>Request Distribution</h2>\n";
    for (const auto &metric : distribution) {
        write_bar(out, metric, max_value);
    }
    out << "</section>\n"
        << "</main>\n"
        << "</body>\n"
        << "</html>\n";

    return true;
}

} // namespace dnsrelay
