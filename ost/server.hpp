#ifndef RAWSTOR_OSTBACKEND_SERVER_HPP
#define RAWSTOR_OSTBACKEND_SERVER_HPP

#include <rawstd/uri.hpp>

#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawstor {
namespace ostbackend {

class Session;

class Server final {
private:
    RawIOQueue* _queue;
    int _fd;
    std::vector<rawstd::URI> _locations;
    RawIOEvent* _accept_event;
    std::unordered_map<int, std::shared_ptr<Session>> _sessions;

    static int _accept(int result, void* data) noexcept;
    int _accept(int result);
    void _add_session(int fd);

public:
    Server(
        unsigned int queue_size, const std::string& addr, unsigned int port,
        const char* location
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    inline const std::vector<rawstd::URI>& locations() const noexcept {
        return _locations;
    }

    void del_session(int fd) noexcept;
    void loop();

    // Sends a response frame to fd, tearing the session down via
    // del_session() if the send itself fails (e.g. a short write).
    void send_response(
        int fd, const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
        uint64_t hash
    );
    void send_response(
        int fd, const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
        uint64_t hash, const std::shared_ptr<std::vector<unsigned char>>& data
    );
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SERVER_HPP
