#ifndef RAWSTOR_OSTBACKEND_TESTS_CLIENT_HPP
#define RAWSTOR_OSTBACKEND_TESTS_CLIENT_HPP

#include <rawstor/protocol.h>

#include <rawstd/uuid.h>

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace ostbackend {
namespace tests {

// A minimal, synchronous OST-protocol client wrapping one end of an
// already-connected stream socket (see test_session.cpp: a socketpair(),
// the other end handed directly to ostbackend::Client::create() -- no real
// Server, no TCP) -- deliberately not librawstor's own async client, so a
// test controls exactly what bytes go out and when, independent of
// Connection/Session's own pipelining and retry behavior.
class Client final {
private:
    int _fd;
    uint16_t _next_cid;

public:
    // Takes ownership of fd (closed by the destructor).
    explicit Client(int fd);
    Client(const Client&) = delete;
    Client(Client&&) = delete;
    ~Client();

    Client& operator=(const Client&) = delete;
    Client& operator=(Client&&) = delete;

    // Each send_*() returns the cid it used, for matching against the
    // eventual recv_response().
    uint16_t send_allocate(const RawstdUUID& id, uint64_t size);
    uint16_t send_set_object(const RawstdUUID& id);
    uint16_t
    send_write(uint64_t offset, const void* buf, size_t size, bool sync);
    uint16_t send_read(uint64_t offset, uint32_t size);
    uint16_t send_discard(uint64_t offset, uint32_t size);
    uint16_t send_write_zeroes(uint64_t offset, uint32_t size, bool unmap);

    // Blocking: reads exactly one response frame, then -- if payload_size
    // is nonzero (a READ response) -- that many bytes of payload after
    // it.
    RawstorOSTFrameResponse
    recv_response(void* payload = nullptr, size_t payload_size = 0);

    // Bytes currently queued to read on this socket (SIOCINQ) without
    // blocking -- lets a pump loop know when a response has actually
    // arrived instead of guessing.
    size_t bytes_available() const;
};

} // namespace tests
} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_TESTS_CLIENT_HPP
