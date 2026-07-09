#include "config.h"
#include "relay.h"

// 程序入口：解析命令行参数，然后把配置交给 DNS Relay 主循环。
int main(int argc, char **argv) {
    dnsrelay::Config cfg;
    if (!dnsrelay::parse_args(argc, argv, cfg)) {
        dnsrelay::print_usage(argv[0]);
        return 1;
    }
    return dnsrelay::run_relay(cfg);
}
