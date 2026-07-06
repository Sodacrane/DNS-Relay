#pragma once

#include <cstdint>

namespace dnsrelay {

int create_bound_socket(uint16_t port);
int create_udp_socket();

} // namespace dnsrelay
