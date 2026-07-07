#ifndef RAWSTOR_TESTS_SESSION_HPP
#define RAWSTOR_TESTS_SESSION_HPP

#include <rawstor/protocol.h>

#include <unistd.h>

#include <cstdint>
#include <vector>

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
    void cmd_allocate_response(uint32_t magic, uint16_t cid, int32_t res);
    void cmd_allocate(uint32_t magic, uint16_t cid, int32_t res);

    void cmd_set_object_request();
    void cmd_set_object_response(uint32_t magic, uint16_t cid, int32_t res);
    void cmd_set_object(uint32_t magic, uint16_t cid, int32_t res);

    /*
     * The null-binding SET_OBJECT exchange a client performs before its
     * first control command on a connection (the lazy handshake).
     */
    void cmd_handshake();

    void cmd_release_request();
    void cmd_release_response(uint32_t magic, uint16_t cid, int32_t res);
    void cmd_release(uint32_t magic, uint16_t cid, int32_t res);

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
    void cmd_read_error(uint32_t magic, uint16_t cid, int32_t res);

    void cmd_write_request(size_t size);
    void cmd_write_response(uint32_t magic, uint16_t cid, int32_t res);
    void cmd_write(uint32_t magic, uint16_t cid, int32_t res);

    void cmd_spec_request();
    void cmd_spec_response(
        uint32_t magic, uint16_t cid, int32_t res,
        const RawstorOSTFrameMetaBody& meta
    );
    void cmd_spec(
        uint32_t magic, uint16_t cid, int32_t res,
        const RawstorOSTFrameMetaBody& meta
    );

    void cmd_set_state_request();
    void cmd_set_state_response(uint32_t magic, uint16_t cid, int32_t res);
    void cmd_set_state(uint32_t magic, uint16_t cid, int32_t res);

    void cmd_snapshot_request();
    void cmd_snapshot_response(
        RawstorOSTCommandType cmd, uint32_t magic, uint16_t cid, int32_t res
    );
    /* cmd = RAWSTOR_CMD_SNAPSHOT or RAWSTOR_CMD_SNAP_REMOVE. */
    void cmd_snapshot(
        RawstorOSTCommandType cmd, uint32_t magic, uint16_t cid, int32_t res
    );

    void cmd_list_request();
    void cmd_list_response(
        uint32_t magic, uint16_t cid, int32_t res,
        const std::vector<RawstorOSTFrameMetaBody>& records
    );
    void cmd_list(
        uint32_t magic, uint16_t cid, int32_t res,
        const std::vector<RawstorOSTFrameMetaBody>& records
    );

    void cmd_flush_request();
    void cmd_flush_response(uint32_t magic, uint16_t cid, int32_t res);
    void cmd_flush(uint32_t magic, uint16_t cid, int32_t res);
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_SESSION_HPP
