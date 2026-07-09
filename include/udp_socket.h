#pragma once

#include <cstdint>

namespace dnsrelay {

// 创建 UDP socket；监听 socket 会绑定到本地端口，上游 socket 只负责收发。
int create_bound_socket(uint16_t port);
int create_udp_socket();

} // namespace dnsrelay
