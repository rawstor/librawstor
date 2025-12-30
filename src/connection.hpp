#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include <rawstorstd/uri.hpp>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <memory>
#include <vector>

#include <cstddef>

namespace rawstor {

class TaskScalar;

class TaskVector;

class Session;

class Connection final {
private:
    RawstorObject* _object;
    unsigned int _depth;

    std::vector<std::shared_ptr<Session>> _sessions;
    size_t _session_index;

    std::vector<std::shared_ptr<Session>>
    _open(const URI& uri, RawstorObject* object, size_t nsessions);

public:
    Connection(unsigned int depth);
    Connection(const Connection&) = delete;
    ~Connection();

    Connection& operator=(const Connection&) = delete;

    std::shared_ptr<Session> get_next_session();
    void invalidate_session(const std::shared_ptr<Session>& s);

    const URI* uri() const noexcept;

    void create(const URI& uri, const RawstorObjectSpec& sp);

    void remove(const URI& uri);

    void spec(const URI& uri, RawstorObjectSpec* sp);

    void open(const URI& uri, RawstorObject* object, size_t nsessions);

    void close();

    void read(std::unique_ptr<TaskScalar> t);

    void read(std::unique_ptr<TaskVector> t);

    void write(std::unique_ptr<TaskScalar> t);

    void write(std::unique_ptr<TaskVector> t);
};

} // namespace rawstor

#endif // RAWSTOR_CONNECTION_HPP
