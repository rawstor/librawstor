#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/object.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <cstring>
#include <memory>

namespace {

// Covers the backport shim (include/rawstor/object.h's deprecated names)
// against a real file:// backend -- the risky, hand-written half of this
// commit (blocking pumps, per-call trampoline context lifetime, the
// id()/location() target-string round-trip), as opposed to the _v2 names
// already exercised (under their own names) by every other test in this
// binary.

struct PreadResult {
    RawstorObject* object;
    size_t size;
    size_t result;
    int error;
    bool done;
};

int pread_cb(
    RawstorObject* object, size_t size, size_t result, int error, void* data
) {
    auto* r = static_cast<PreadResult*>(data);
    r->object = object;
    r->size = size;
    r->result = result;
    r->error = error;
    r->done = true;
    return 0;
}

TEST(LegacyObjectApiTest, create_at_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    std::string location = rawstd::URI(dir.uri()).str();

    RawstorObjectSpec spec{.size = 1ull << 20};

    // Buffer too small: create_at() must not create the object, and must
    // report the required length synchronously via its own return value.
    char tiny[1];
    int res = rawstor_object_create_at(
        location.c_str(), nullptr, &spec, tiny, sizeof(tiny)
    );
    ASSERT_GT(res, (int)sizeof(tiny));

    // Buffer large enough: the object is actually created this time.
    char target[256];
    res = rawstor_object_create_at(
        location.c_str(), nullptr, &spec, target, sizeof(target)
    );
    ASSERT_GE(res, 0);
    ASSERT_LT((size_t)res, sizeof(target));

    RawstorObjectSpec got{};
    ASSERT_EQ(rawstor_object_spec(target, &got), 0);
    EXPECT_EQ(got.size, spec.size);

    RawstorStringList* targets = nullptr;
    RawstorPaginationToken token{};
    ASSERT_EQ(rawstor_object_list(location.c_str(), 0, &targets, &token), 0);
    ASSERT_NE(targets, nullptr);
    bool found = false;
    for (const char** it = rawstor_string_list_iter(targets); it != nullptr;
         it = rawstor_string_list_next(it)) {
        if (std::string(*it) == target) {
            found = true;
        }
    }
    EXPECT_TRUE(found);
    rawstor_string_list_delete(targets);

    EXPECT_EQ(rawstor_object_remove(target), 0);
    EXPECT_EQ(rawstor_object_spec(target, &got), -ENOENT);
}

TEST(LegacyObjectApiTest, create_open_io_close_remove) {
    rawstor::tests::TmpDir dir;
    std::string location = rawstd::URI(dir.uri()).str();
    std::string uuid = "00000000-0000-7000-8000-000000000042";
    std::string target = rawstd::URI(rawstd::URI(location), uuid).str();

    RawstorObjectSpec spec{.size = 4096};
    ASSERT_EQ(rawstor_object_create(target.c_str(), &spec), 0);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
    RawstorObject* object = nullptr;
    ASSERT_EQ(rawstor_object_open(queue.get(), target.c_str(), &object), 0);
    ASSERT_NE(object, nullptr);

    // id()/location() round-trip: purely syntactic, no I/O needed.
    char id_buf[64];
    int ires = rawstor_object_id(object, id_buf, sizeof(id_buf));
    ASSERT_GE(ires, 0);
    EXPECT_EQ(std::string(id_buf), uuid);

    char loc_buf[256];
    int lres = rawstor_object_location(object, loc_buf, sizeof(loc_buf));
    ASSERT_GE(lres, 0);
    EXPECT_EQ(std::string(loc_buf), location);

    const char wbuf[] = "legacy pread/pwrite roundtrip";

    PreadResult wres{};
    int res = rawstor_object_pwrite(
        object, wbuf, sizeof(wbuf), 0, /*sync=*/true, pread_cb, &wres
    );
    ASSERT_EQ(res, 0);
    while (!wres.done) {
        ASSERT_GE(rawio_wait(queue.get()), 0);
    }
    EXPECT_EQ(wres.object, object);
    EXPECT_EQ(wres.size, sizeof(wbuf));
    EXPECT_EQ(wres.error, 0);
    EXPECT_EQ(wres.result, sizeof(wbuf));

    PreadResult fres{};
    res = rawstor_object_flush(object, pread_cb, &fres);
    ASSERT_EQ(res, 0);
    while (!fres.done) {
        ASSERT_GE(rawio_wait(queue.get()), 0);
    }
    EXPECT_EQ(fres.error, 0);

    char rbuf[sizeof(wbuf)];
    PreadResult rres{};
    res = rawstor_object_pread(object, rbuf, sizeof(rbuf), 0, pread_cb, &rres);
    ASSERT_EQ(res, 0);
    while (!rres.done) {
        ASSERT_GE(rawio_wait(queue.get()), 0);
    }
    EXPECT_EQ(rres.error, 0);
    EXPECT_EQ(rres.result, sizeof(rbuf));
    EXPECT_EQ(std::string(rbuf), std::string(wbuf));

    // Vectored variants, exercised once each -- same trampoline as the
    // scalar calls above.
    iovec wiov{.iov_base = const_cast<char*>(wbuf), .iov_len = sizeof(wbuf)};
    PreadResult wvres{};
    res = rawstor_object_pwritev(
        object, &wiov, 1, sizeof(wbuf), 0, /*sync=*/false, pread_cb, &wvres
    );
    ASSERT_EQ(res, 0);
    while (!wvres.done) {
        ASSERT_GE(rawio_wait(queue.get()), 0);
    }
    EXPECT_EQ(wvres.error, 0);
    EXPECT_EQ(wvres.result, sizeof(wbuf));

    char rvbuf[sizeof(wbuf)];
    iovec riov{.iov_base = rvbuf, .iov_len = sizeof(rvbuf)};
    PreadResult rvres{};
    res = rawstor_object_preadv(
        object, &riov, 1, sizeof(rvbuf), 0, pread_cb, &rvres
    );
    ASSERT_EQ(res, 0);
    while (!rvres.done) {
        ASSERT_GE(rawio_wait(queue.get()), 0);
    }
    EXPECT_EQ(rvres.error, 0);
    EXPECT_EQ(rvres.result, sizeof(rvbuf));
    EXPECT_EQ(std::string(rvbuf), std::string(wbuf));

    EXPECT_EQ(rawstor_object_close(object), 0);
    EXPECT_EQ(rawstor_object_remove(target.c_str()), 0);
}

} // namespace
