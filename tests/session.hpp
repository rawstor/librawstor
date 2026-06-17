#ifndef RAWSTOR_TESTS_SESSION_HPP
#define RAWSTOR_TESTS_SESSION_HPP

#include <unistd.h>

#include <cstdint>

namespace rawstor {
namespace tests {

class Server;

class Session final {
private:
    rawstor::tests::Server& _server;

public:
    explicit Session(rawstor::tests::Server& server);

    ~Session();

    void cmd_allocate_request();
    void cmd_allocate_response();
    void cmd_allocate();

    void cmd_set_object_request();
    void cmd_set_object_response(uint32_t magic, uint16_t cid, int32_t res);
    void cmd_set_object(uint32_t magic, uint16_t cid, int32_t res);

    void cmd_read_request();
    void cmd_read_response(
        uint32_t magic, uint16_t cid, const void* buf, size_t size,
        uint64_t hash
    );
    void cmd_read_response(
        uint32_t magic, uint16_t cid, const void* buf, size_t size
    );
    void cmd_read(
        uint32_t magic, uint16_t cid, const void* buf, size_t size,
        uint64_t hash
    );
    void cmd_read(uint32_t magic, uint16_t cid, const void* buf, size_t size);

    void cmd_write_request(size_t size);
    void cmd_write_response(uint32_t magic, uint16_t cid, int32_t res);
    void cmd_write(uint32_t magic, uint16_t cid, int32_t res);
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_SESSION_HPP
