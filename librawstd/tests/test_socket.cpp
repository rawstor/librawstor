#include "rawstd/socket.h"

#include "rawstd/logging.h"

#include <gtest/gtest.h>

#include <arpa/inet.h>

#include <cerrno>

namespace {

class SocketTest : public ::testing::Test {
protected:
    // Resolution failures are logged.
    static void SetUpTestSuite() { ASSERT_EQ(rawstd_logging_initialize(), 0); }
    static void TearDownTestSuite() { rawstd_logging_terminate(); }
};

TEST_F(SocketTest, resolve_ip) {
    sockaddr_in addr = {};
    ASSERT_EQ(rawstd_socket_resolve("127.0.0.1", 8080, &addr), 0);
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(ntohs(addr.sin_port), 8080);
    EXPECT_EQ(ntohl(addr.sin_addr.s_addr), INADDR_LOOPBACK);
}

TEST_F(SocketTest, resolve_hostname) {
    sockaddr_in addr = {};
    ASSERT_EQ(rawstd_socket_resolve("localhost", 8080, &addr), 0);
    EXPECT_EQ(addr.sin_family, AF_INET);
    EXPECT_EQ(ntohs(addr.sin_port), 8080);
    EXPECT_EQ(ntohl(addr.sin_addr.s_addr), INADDR_LOOPBACK);
}

TEST_F(SocketTest, resolve_all) {
    sockaddr_in addrs[4] = {};
    size_t count = 4;
    ASSERT_EQ(rawstd_socket_resolve_all("localhost", 8080, addrs, &count), 0);
    ASSERT_GE(count, 1u);
    ASSERT_LE(count, 4u);
    for (size_t i = 0; i < count; ++i) {
        EXPECT_EQ(addrs[i].sin_family, AF_INET);
        EXPECT_EQ(ntohs(addrs[i].sin_port), 8080);
        EXPECT_EQ(ntohl(addrs[i].sin_addr.s_addr) >> 24, 127u);
    }
}

TEST_F(SocketTest, resolve_invalid) {
    sockaddr_in addr = {};
    EXPECT_EQ(rawstd_socket_resolve("host.invalid", 8080, &addr), -EINVAL);
    EXPECT_EQ(rawstd_socket_resolve("127.0.0.1", 65536, &addr), -EINVAL);
}

} // namespace
