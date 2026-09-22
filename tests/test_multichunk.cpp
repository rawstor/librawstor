#include "chunk.hpp"
#include "object.hpp"
#include "opts.h"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace {

// Duplicate of chunk.cpp's own `run()` -- see that one's doc comment for
// why it isn't shared.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

// Builds a target string naming two chunk groups of one object by hand
// (docs/locations_and_targets.md): "<location>/<uuid>/0" and
// "<location>/<uuid>/<chunk_size>" -- the same flat, offset-sorted URI
// list a real chunk-placement caller (rawstor-mds, in a later bucket)
// would build, just typed out here instead. Nothing about Target/Object
// requires that caller to exist; group_by_offset()/Target::open()'s own
// multi-chunk machinery only ever looks at the URIs themselves.
std::vector<rawstd::URI> two_chunk_uris(
    const rawstd::URI& location, const std::string& uuid_string,
    uint64_t chunk_size
) {
    rawstd::URI id_uri(location, uuid_string);
    return {
        rawstd::URI(id_uri, "0"),
        rawstd::URI(id_uri, std::to_string(chunk_size)),
    };
}

} // namespace

// An object spanning two chunk groups: create() splits its own size at
// the chunk_size boundary (one full-size chunk plus one short, final
// chunk), and open() builds a single Object routing reads/writes across
// both, entirely from the target string's own two offset-tagged URIs --
// no chunk-placement service involved.
TEST(MultiChunkTest, create_open_read_write_across_chunk_boundary) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    const uint64_t chunk_size = 64 * 1024;
    const uint64_t total_size = chunk_size + (32 * 1024); // short last chunk

    rawstor::Target target(two_chunk_uris(location, uuid_string, chunk_size));

    RawstorObjectSpec spec{
        .size = total_size,
        .width = 1,
        .chunk_size = chunk_size,
    };
    run(*queue, target.create(*queue, spec));

    std::unique_ptr<rawstor::Object> object = run(*queue, target.open(*queue));

    // A write straddling the chunk boundary must land split across both
    // chunks and read back whole.
    std::vector<char> pattern(16);
    for (size_t i = 0; i < pattern.size(); ++i) {
        pattern[i] = static_cast<char>('a' + i);
    }
    off_t straddle_offset = static_cast<off_t>(chunk_size) - 8;
    size_t written =
        run(*queue,
            object->pwrite(
                pattern.data(), pattern.size(), straddle_offset, /*sync=*/true
            ));
    EXPECT_EQ(written, pattern.size());

    std::vector<char> readback(pattern.size());
    size_t read =
        run(*queue,
            object->pread(readback.data(), readback.size(), straddle_offset));
    EXPECT_EQ(read, readback.size());
    EXPECT_EQ(readback, pattern);

    // A write entirely inside the short, final chunk must also round-trip.
    off_t last_chunk_offset = static_cast<off_t>(chunk_size) + 4;
    size_t written2 =
        run(*queue,
            object->pwrite(
                pattern.data(), pattern.size(), last_chunk_offset, /*sync=*/true
            ));
    EXPECT_EQ(written2, pattern.size());

    std::vector<char> readback2(pattern.size());
    size_t read2 = run(
        *queue,
        object->pread(readback2.data(), readback2.size(), last_chunk_offset)
    );
    EXPECT_EQ(read2, readback2.size());
    EXPECT_EQ(readback2, pattern);

    // Reading/writing past the object's own total size (short last chunk
    // included) is rejected, same as a plain, single-chunk object.
    std::vector<char> oob(1);
    EXPECT_THROW(
        run(*queue, object->pread(oob.data(), oob.size(), total_size)),
        std::system_error
    );

    run(*queue, object->close());
    run(*queue, target.remove(*queue));
}
