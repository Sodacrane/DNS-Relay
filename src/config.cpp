#include "config.h"

#include "utils.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace dnsrelay {

void print_usage(const char *program) {
    std::cerr
        << "Usage: " << program << " [-d|-dd] [-p listen-port] [-l log-file]\n"
        << "       [--cache-file file] [--no-cache-file] [--cache-min-ttl seconds]\n"
        << "       [--cache-max-ttl seconds] [--cache-capacity entries]\n"
        << "       [--stats-file file] [--no-stats] [dns-server-ipaddr] [filename]\n"
        << "Example for normal DNS port: sudo " << program << " -d 114.114.114.114 dnsrelay.txt\n"
        << "Example for WSL test port:   " << program << " -dd -p 1053 114.114.114.114 dnsrelay.txt\n"
        << "Example with cache tuning:   " << program << " -dd -p 1053 --cache-min-ttl 30 --cache-max-ttl 600 --cache-capacity 1024 114.114.114.114 dnsrelay.txt\n";
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
        if (arg == "--cache-file") {
            if (i + 1 >= argc) {
                std::cerr << "Missing cache file name.\n";
                return false;
            }
            cfg.cache_file = argv[++i];
            cfg.persistent_cache = true;
            continue;
        }
        if (arg == "--cache-min-ttl") {
            if (i + 1 >= argc || !parse_u32(argv[++i], cfg.cache_min_ttl)) {
                std::cerr << "Invalid cache minimum TTL.\n";
                return false;
            }
            continue;
        }
        if (arg == "--cache-max-ttl") {
            if (i + 1 >= argc || !parse_u32(argv[++i], cfg.cache_max_ttl)) {
                std::cerr << "Invalid cache maximum TTL.\n";
                return false;
            }
            continue;
        }
        if (arg == "--cache-capacity") {
            uint32_t capacity = 0;
            if (i + 1 >= argc || !parse_u32(argv[++i], capacity)) {
                std::cerr << "Invalid cache capacity.\n";
                return false;
            }
            cfg.cache_capacity = capacity;
            continue;
        }
        if (arg == "--stats-file") {
            if (i + 1 >= argc) {
                std::cerr << "Missing stats file name.\n";
                return false;
            }
            cfg.stats_file = argv[++i];
            cfg.stats_report = true;
            continue;
        }
        if (arg == "--no-log") {
            cfg.logging = false;
            continue;
        }
        if (arg == "--no-cache-file") {
            cfg.persistent_cache = false;
            continue;
        }
        if (arg == "--no-stats") {
            cfg.stats_report = false;
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
    if (cfg.cache_min_ttl > cfg.cache_max_ttl) {
        std::cerr << "Cache minimum TTL cannot be greater than cache maximum TTL.\n";
        return false;
    }
    return true;
}

} // namespace dnsrelay
