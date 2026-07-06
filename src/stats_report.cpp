#include "stats_report.h"

#include "utils.h"

#include <algorithm>
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

void write_metric_card(std::ostream &out, const Metric &metric, uint64_t total) {
    out << "<section class=\"metric\" style=\"--accent:" << metric.accent << "\">"
        << "<div class=\"metric-label\">" << html_escape(metric.label) << "</div>"
        << "<div class=\"metric-value\">" << metric.value << "</div>"
        << "<div class=\"metric-sub\">" << percent(metric.value, total) << " of queries</div>"
        << "</section>\n";
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

    const std::vector<Metric> metrics = {
        {"Local hits", stats.local_hits, "#2f8f5b"},
        {"Local blocks", stats.local_blocks, "#c2410c"},
        {"Wildcard hits", stats.wildcard_hits, "#7c3aed"},
        {"Cache hits", stats.cache_hits, "#2563eb"},
        {"Forwarded", stats.forwarded, "#b7791f"},
        {"Upstream responses", stats.upstream_responses, "#0f766e"},
        {"Bad queries", stats.bad_queries, "#b91c1c"},
        {"Timeouts", stats.timeouts, "#64748b"}
    };

    uint64_t max_value = 1;
    for (const auto &metric : metrics) {
        max_value = std::max(max_value, metric.value);
    }

    const uint64_t served_by_relay = stats.local_hits + stats.local_blocks + stats.cache_hits;
    const uint64_t total = std::max<uint64_t>(stats.total_queries, 1);

    out << "<!doctype html>\n"
        << "<html lang=\"en\">\n"
        << "<head>\n"
        << "<meta charset=\"utf-8\">\n"
        << "<meta http-equiv=\"refresh\" content=\"2\">\n"
        << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        << "<title>DNS Relay Dashboard</title>\n"
        << "<style>\n"
        << ":root{color-scheme:light;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f6f7f9;color:#172033;}\n"
        << "*{box-sizing:border-box}body{margin:0;padding:24px;background:#f6f7f9;}\n"
        << "main{max-width:1120px;margin:0 auto;display:grid;gap:16px;}\n"
        << "header{display:flex;justify-content:space-between;gap:16px;align-items:flex-end;border-bottom:1px solid #d9dde5;padding-bottom:14px;}\n"
        << "h1{font-size:28px;line-height:1.15;margin:0;color:#111827;font-weight:720;letter-spacing:0;}\n"
        << ".updated{font-size:13px;color:#5d6678;text-align:right;}\n"
        << ".summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;}\n"
        << ".metric,.panel{background:#fff;border:1px solid #dde2ea;border-radius:8px;box-shadow:0 1px 2px rgba(15,23,42,.04);}\n"
        << ".metric{padding:14px;border-top:4px solid var(--accent);min-height:112px;}\n"
        << ".metric-label{font-size:13px;color:#5c6678;font-weight:650;}\n"
        << ".metric-value{font-size:30px;font-weight:760;color:#101828;margin-top:12px;}\n"
        << ".metric-sub{font-size:12px;color:#687385;margin-top:8px;}\n"
        << ".grid{display:grid;grid-template-columns:1.35fr .65fr;gap:16px;align-items:start;}\n"
        << ".panel{padding:16px;}\n"
        << "h2{font-size:17px;margin:0 0 14px;color:#172033;letter-spacing:0;}\n"
        << ".bar-row{display:grid;grid-template-columns:150px 1fr 72px;gap:12px;align-items:center;margin:12px 0;}\n"
        << ".bar-name{font-size:13px;color:#384153;font-weight:620;}\n"
        << ".bar-track{height:14px;background:#e8ecf2;border-radius:999px;overflow:hidden;}\n"
        << ".bar-fill{height:100%;min-width:0;border-radius:999px;}\n"
        << ".bar-count{text-align:right;font-variant-numeric:tabular-nums;color:#172033;font-weight:700;}\n"
        << ".kv{display:grid;grid-template-columns:120px 1fr;gap:9px 12px;font-size:13px;}\n"
        << ".kv dt{color:#687385;font-weight:650;}.kv dd{margin:0;color:#172033;word-break:break-word;}\n"
        << ".ratio{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px;}\n"
        << ".ratio div{background:#f1f4f8;border:1px solid #dce2ea;border-radius:8px;padding:10px;}\n"
        << ".ratio strong{display:block;font-size:20px;color:#101828;margin-bottom:4px;}\n"
        << ".ratio span{font-size:12px;color:#687385;}\n"
        << "@media(max-width:820px){body{padding:14px}.summary,.grid{grid-template-columns:1fr}.bar-row{grid-template-columns:112px 1fr 52px}header{align-items:flex-start;flex-direction:column}.updated{text-align:left}}\n"
        << "</style>\n"
        << "</head>\n"
        << "<body>\n"
        << "<main>\n"
        << "<header><div><h1>DNS Relay Dashboard</h1></div><div class=\"updated\">Updated "
        << html_escape(time_string()) << "<br>Auto refresh: 2s</div></header>\n"
        << "<section class=\"summary\">\n";

    write_metric_card(out, {"Total queries", stats.total_queries, "#111827"}, total);
    write_metric_card(out, {"Served locally", served_by_relay, "#2f8f5b"}, total);
    write_metric_card(out, {"Forwarded", stats.forwarded, "#b7791f"}, total);
    write_metric_card(out, {"Cache hits", stats.cache_hits, "#2563eb"}, total);

    out << "</section>\n"
        << "<section class=\"grid\">\n"
        << "<div class=\"panel\"><h2>Request Distribution</h2>\n";

    for (const auto &metric : metrics) {
        write_bar(out, metric, max_value);
    }

    out << "</div>\n"
        << "<aside class=\"panel\"><h2>Runtime</h2>\n"
        << "<dl class=\"kv\">"
        << "<dt>Listen port</dt><dd>" << info.config.listen_port << "</dd>"
        << "<dt>Upstream</dt><dd>" << html_escape(info.config.upstream_ip) << "</dd>"
        << "<dt>Hosts file</dt><dd>" << html_escape(info.config.hosts_file) << "</dd>"
        << "<dt>Log file</dt><dd>" << (info.config.logging ? html_escape(info.config.log_file) : "disabled") << "</dd>"
        << "<dt>Cache file</dt><dd>" << (info.config.persistent_cache ? html_escape(info.config.cache_file) : "disabled") << "</dd>"
        << "<dt>Cache entries</dt><dd>" << info.cache_entries << "</dd>"
        << "<dt>Pending queries</dt><dd>" << info.pending_queries << "</dd>"
        << "</dl>\n"
        << "<div class=\"ratio\">"
        << "<div><strong>" << percent(served_by_relay, total) << "</strong><span>answered without upstream</span></div>"
        << "<div><strong>" << percent(stats.cache_hits, total) << "</strong><span>cache hit rate</span></div>"
        << "</div>\n"
        << "</aside>\n"
        << "</section>\n"
        << "</main>\n"
        << "</body>\n"
        << "</html>\n";

    return true;
}

} // namespace dnsrelay
