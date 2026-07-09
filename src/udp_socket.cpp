#include "udp_socket.h"

#include <arpa/inet.h>

#include <stdexcept>
#include <string>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace dnsrelay {

// 创建并绑定监听 socket，客户端的 DNS 查询会发到这个端口。
int create_bound_socket(uint16_t port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("socket() failed");
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        close(sock);
        throw std::runtime_error("bind UDP port " + std::to_string(port) + " failed");
    }
    return sock;
}

// 创建普通 UDP socket，用来向上游 DNS 发送请求并接收响应。
int create_udp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("socket() for upstream failed");
    }
    return sock;
}

} // namespace dnsrelay
