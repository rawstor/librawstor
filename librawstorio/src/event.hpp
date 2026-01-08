#ifndef RAWSTORIO_EVENT_HPP
#define RAWSTORIO_EVENT_HPP

#include <rawstorstd/logging.h>

#include <sys/socket.h>
#include <sys/uio.h>

#include <string>

namespace rawstor {
namespace io {

class Event {
public:
    Event() = default;
    Event(const Event&) = delete;
    Event(Event&&) = delete;
    virtual ~Event() = default;
    Event& operator=(const Event&) = delete;
    Event& operator=(Event&&) = delete;
};

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_EVENT_HPP
