#include "config.h"
#include "relay.h"

int main(int argc, char **argv) {
    dnsrelay::Config cfg;
    if (!dnsrelay::parse_args(argc, argv, cfg)) {
        dnsrelay::print_usage(argv[0]);
        return 1;
    }
    return dnsrelay::run_relay(cfg);
}
