#include "config.h"

#include "utils.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace dnsrelay {

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

} // namespace dnsrelay
