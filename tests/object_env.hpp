#ifndef RAWSTOR_TESTS_OBJECT_ENV_HPP
#define RAWSTOR_TESTS_OBJECT_ENV_HPP

#include "tmp_dir.hpp"

#include <string>
#include <thread>

namespace rawstor {
namespace tests {

// A live rawstor-mds + rawstor-ost pair, each driven on its own
// background thread with its own RawIOQueue -- mirroring how the real
// binaries run them (mds/main.cpp's single Server::loop(), ost/src/
// main.cpp's per-worker one) -- so a test can exercise rawstor::Object's
// real MDS/OST wire path (mds_client.cpp, ost_backend.cpp) end to end,
// the same way tests/test_mirror.cpp's tests::Server exercises the OST
// wire protocol for plain Chunks. The OST's one backend is a fresh
// TmpDir's file:// -- the only backend guaranteed available in a build/
// test environment, which means every chunk's Backend::create_snapshot()/
// remove() with a non-nil snap_id always answers -ENOTSUP (docs/mds.md:
// "file:// backend has no CoW"). That is exactly the negative path this
// environment exists to exercise end to end (the reservation/rollback
// bookkeeping around a failed CoW); the real CoW positive path needs a
// live zfs pool, out of reach in a portable test.
class ObjectEnv {
private:
    TmpDir _ost_dir;
    TmpDir _mds_dir;
    int _ost_listen_fd;
    int _ost_wake_write_fd;
    int _mds_wake_write_fd;
    std::thread _ost_thread;
    std::thread _mds_thread;
    unsigned int _mds_port;

public:
    // Binds both servers synchronously before returning (a background
    // thread's own bind()/listen() racing the first test call's connect()
    // would otherwise make this flaky) -- see the .cpp file's own doc
    // comment on how.
    ObjectEnv(unsigned int mds_port, unsigned int ost_port);
    ObjectEnv(const ObjectEnv&) = delete;
    ObjectEnv(ObjectEnv&&) = delete;
    ~ObjectEnv();

    ObjectEnv& operator=(const ObjectEnv&) = delete;
    ObjectEnv& operator=(ObjectEnv&&) = delete;

    // "mds://127.0.0.1:<mds_port>" -- every test target in this
    // environment is built under this location.
    std::string location() const;
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_OBJECT_ENV_HPP
