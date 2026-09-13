// Exercises VirtQueue's ownership/lifecycle layer (start()/stop(),
// post_*()/get_vring_base() crossing the real thread boundary) against a
// real file:// object -- unlike test_virtqueue.cpp's pure ring-mechanism
// tests, these need an actual RawIOQueue+RawstorObject, since that's what
// start() creates on its own thread. See vhost/src/virtqueue.cpp's
// top-of-file comment and vhost/include/vhost/virtqueue.hpp's class
// comment for the design this is testing.

#include <vhost/virtqueue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uuid.h>

#include <rawstor/rawio.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

using rawstor::vhost::VirtQueue;

constexpr unsigned int kQueueSize = 8;

// Mirrors device.cpp's own Result/result_cb/spec_object -- see that
// file's doc comment for why every rawstor_target_*() C-ABI call in this
// codebase spins its own bootstrap queue the same way.
struct Result {
    int error = 0;
    bool done = false;
};

int result_cb(ssize_t result, void* data) {
    Result* r = static_cast<Result*>(data);
    r->error = result < 0 ? static_cast<int>(-result) : 0;
    r->done = true;
    return 0;
}

void spin(RawIOQueue* queue, Result& result) {
    while (!result.done) {
        int res = rawio_wait(queue);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
    if (result.error) {
        RAWSTD_THROW_SYSTEM_ERROR(result.error);
    }
}

std::string make_uuid() {
    RawstdUUID id;
    if (rawstd_uuid7_init(&id) != 0) {
        throw std::runtime_error("rawstd_uuid7_init() failed");
    }
    RawstdUUIDString s;
    rawstd_uuid_to_string(&id, &s);
    return s;
}

// rawstor_initialize()/rawstor_terminate() bracket the whole binary, in
// main.cpp -- not per-test here, matching the one real Server instance a
// production process ever has.

// Stands up a fresh, empty file:// object in a scratch temp directory and
// returns its target string ("file:///tmp/.../<uuid>"), ready for
// VirtQueue::start(). The directory (and the object in it) is torn down
// when the returned RAII guard goes out of scope.
class ScratchTarget final {
private:
    std::filesystem::path _dir;
    std::string _target;

public:
    explicit ScratchTarget(size_t size = 1u << 20) {
        std::string tmpl =
            (std::filesystem::temp_directory_path() / "rawstor-vq-XXXXXX")
                .string();
        if (mkdtemp(tmpl.data()) == nullptr) {
            RAWSTD_THROW_ERRNO();
        }
        _dir = tmpl;

        std::ostringstream oss;
        oss << "file://" << _dir.string() << "/" << make_uuid();
        _target = oss.str();

        RawIOQueue* queue = nullptr;
        int res = rawio_queue_create(kQueueSize, &queue);
        if (res) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        try {
            RawstorObjectSpec spec{};
            spec.size = size;
            spec.mirrors = 1;
            Result result;
            res = rawstor_target_create(
                queue, _target.c_str(), &spec, result_cb, &result
            );
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
            spin(queue, result);
        } catch (...) {
            rawio_queue_delete(queue);
            throw;
        }
        rawio_queue_delete(queue);
    }

    ScratchTarget(const ScratchTarget&) = delete;
    ScratchTarget(ScratchTarget&&) = delete;

    ~ScratchTarget() {
        std::error_code ec;
        std::filesystem::remove_all(_dir, ec);
    }

    ScratchTarget& operator=(const ScratchTarget&) = delete;
    ScratchTarget& operator=(ScratchTarget&&) = delete;

    const std::string& target() const noexcept { return _target; }
};

// None of the tests below call attach(): everything they exercise --
// start()/stop(), the command queue's post_set_vring_base()/
// get_vring_base(), pause() with nothing in flight -- only ever reaches
// VirtQueue's own state, never Device's (see pause()'s own test for the
// one thing that would touch it, and why it's avoided here). Standing up
// a real Device (itself spawning its own VirtQueue threads) just to hand
// out a reference nothing below reads isn't worth the weight.
class VirtQueueWorkerTest : public ::testing::Test {
protected:
    ScratchTarget scratch;
};

} // namespace

TEST_F(VirtQueueWorkerTest, StopWithoutStartIsSafeNoOp) {
    VirtQueue vq;
    EXPECT_FALSE(vq.running());
    vq.stop();
    EXPECT_FALSE(vq.running());
}

TEST_F(VirtQueueWorkerTest, StartOpensOwnObjectAndStopJoinsCleanly) {
    // A dummy Device isn't needed here: start() never touches _device.
    VirtQueue vq;
    vq.start(scratch.target(), kQueueSize);
    EXPECT_TRUE(vq.running());

    vq.stop();
    EXPECT_FALSE(vq.running());

    // stop() must be idempotent.
    vq.stop();
    EXPECT_FALSE(vq.running());
}

TEST_F(VirtQueueWorkerTest, StartThrowsOnInvalidTargetAndLeavesNotRunning) {
    // file:// happily creates whatever path it's given on open (it's not
    // a "must already exist" backend the way ost:// is), so a merely
    // missing file doesn't exercise this -- an unrecognized scheme does,
    // rejected before any backend is even chosen.
    VirtQueue vq;
    EXPECT_THROW(
        vq.start("bogus-scheme://nope/not-a-uuid", kQueueSize),
        std::system_error
    );
    EXPECT_FALSE(vq.running());
}

TEST_F(VirtQueueWorkerTest, GetVringBaseRoundTripsAcrossWorkerThread) {
    VirtQueue vq;
    vq.start(scratch.target(), kQueueSize);

    vq.post_set_vring_base(7);
    EXPECT_EQ(vq.get_vring_base(), 7);

    vq.stop();
}

TEST_F(VirtQueueWorkerTest, PauseWithNothingInFlightReturnsImmediately) {
    VirtQueue vq;
    vq.start(scratch.target(), kQueueSize);

    // No descriptor was ever popped on this VirtQueue, so pause() has
    // nothing to wait for -- must not hang. Deliberately not paired with
    // a resume() here: this VirtQueue was never attach()ed to a Device
    // (nothing below needs one), and resume() unconditionally calls
    // process_queue(), which -- unlike pause() itself -- does dereference
    // it. Safe to skip in this narrow, about-to-stop() test; see
    // pause()'s own doc comment for why real callers must still pair it.
    vq.pause();

    vq.stop();
}
