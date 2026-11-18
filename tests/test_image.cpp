// Images (src/image.cpp): export to a file, create from a file and create
// from another object, over a real MDS + OST pair so the multi-chunk
// object path is the one exercised.
#include "object_env.hpp"
#include "rawio_sync.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <cerrno>
#include <cstdlib>

namespace {

const size_t chunk_size = 512ull << 10;

// Drives one image call to its last callback, collecting every call, and
// checks what the progress contract promises: percentages strictly increase
// (so none repeats), nothing but the last call is 100 or negative, and
// nothing follows the last call. Returns 0 when the last call is 100, else
// its negative errno.
template <typename F>
ssize_t image_run(
    rawio::Queue& queue, F&& submit, std::vector<ssize_t>* calls_out = nullptr
) {
    struct Op {
        std::vector<ssize_t> calls;
        bool done = false;
    } op;

    int (*cb)(ssize_t, void*) = [](ssize_t result, void* data) -> int {
        Op* op = static_cast<Op*>(data);
        EXPECT_FALSE(op->done) << "a call after the last one: " << result;
        op->calls.push_back(result);
        op->done = result < 0 || result == 100;
        return 0;
    };

    int res = submit(cb, static_cast<void*>(&op));
    if (res < 0) {
        return res;
    }
    while (!op.done) {
        EXPECT_GE(rawio_wait(&queue), 0);
    }
    // Let anything that would wrongly follow the last call arrive.
    for (int i = 0; i < 4; ++i) {
        rawio_wait_timeout(&queue, 1);
    }

    EXPECT_FALSE(op.calls.empty());
    for (size_t i = 0; i + 1 < op.calls.size(); ++i) {
        EXPECT_GE(op.calls[i], 0);
        EXPECT_LT(op.calls[i], 100);
        if (op.calls[i + 1] >= 0) {
            EXPECT_LT(op.calls[i], op.calls[i + 1]);
        }
    }
    if (calls_out != nullptr) {
        *calls_out = op.calls;
    }
    return op.calls.back() == 100 ? 0 : op.calls.back();
}

ssize_t target_create_from_file(
    rawio::Queue& queue, const std::string& target, const std::string& path,
    const RawstorObjectSpec& spec, std::vector<ssize_t>* calls = nullptr
) {
    return image_run(
        queue,
        [&](auto cb, void* data) {
            return rawstor_target_create_from_file(
                &queue, target.c_str(), path.c_str(), &spec, cb, data
            );
        },
        calls
    );
}

ssize_t target_create_from_target(
    rawio::Queue& queue, const std::string& target, const std::string& source,
    const RawstorObjectSpec& spec, std::vector<ssize_t>* calls = nullptr
) {
    return image_run(
        queue,
        [&](auto cb, void* data) {
            return rawstor_target_create_from_target(
                &queue, target.c_str(), source.c_str(), &spec, cb, data
            );
        },
        calls
    );
}

ssize_t target_export(
    rawio::Queue& queue, const std::string& target, const std::string& path,
    std::vector<ssize_t>* calls = nullptr
) {
    return image_run(
        queue,
        [&](auto cb, void* data) {
            return rawstor_target_export(
                &queue, target.c_str(), path.c_str(), cb, data
            );
        },
        calls
    );
}

ssize_t target_spec(
    rawio::Queue& queue, const std::string& target, RawstorObjectSpec* spec
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_spec(&queue, target.c_str(), spec, cb, data);
    });
}

ssize_t target_remove(rawio::Queue& queue, const std::string& target) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_remove(&queue, target.c_str(), cb, data);
    });
}

std::string
object_target(const rawstor::tests::ObjectEnv& env, const char* uuid) {
    rawstd::URI location_uri(env.location());
    return rawstd::URI(location_uri, uuid).str();
}

std::string pattern(size_t size) {
    std::string ret(size, '\0');
    for (size_t i = 0; i < size; ++i) {
        // Distinct per byte position within and across chunks; a zero
        // stretch in the middle is a hole in a sparse export.
        ret[i] = (i >= size / 3 && i < size / 2)
                     ? '\0'
                     : static_cast<char>(1 + (i * 131 + i / chunk_size) % 251);
    }
    return ret;
}

void write_file(const std::filesystem::path& path, const std::string& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()
    );
}

RawstorObjectSpec mds_spec(uint64_t size) {
    RawstorObjectSpec spec{};
    spec.size = size;
    spec.width = 1;
    spec.chunk_size = chunk_size;
    return spec;
}

} // namespace

// A file becomes a four-chunk object and comes back out byte for byte,
// then the object is copied to a second one, which exports the same bytes.
TEST(ImageTest, file_to_object_to_object_to_file) {
    rawstor::tests::ObjectEnv env(8920, 8921);
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    std::string data = pattern(4 * chunk_size);
    write_file(dir.path() / "in.img", data);
    std::string first =
        object_target(env, "018f4e2a-4000-7000-8000-000000000001");
    std::string second =
        object_target(env, "018f4e2a-4000-7000-8000-000000000002");

    std::vector<ssize_t> calls;
    ASSERT_EQ(
        target_create_from_file(
            *queue, first, (dir.path() / "in.img").string(), mds_spec(0), &calls
        ),
        0
    );
    // 2 MiB in 1 MiB blocks: at least the start, the half and the end.
    EXPECT_GE(calls.size(), 3u);
    EXPECT_EQ(calls.front(), 0);
    EXPECT_EQ(calls.back(), 100);
    RawstorObjectSpec spec{};
    ASSERT_EQ(target_spec(*queue, first, &spec), 0);
    EXPECT_EQ(spec.size, data.size());

    ASSERT_EQ(
        target_export(*queue, first, (dir.path() / "first.img").string()), 0
    );
    EXPECT_EQ(read_file(dir.path() / "first.img"), data);

    ASSERT_EQ(target_create_from_target(*queue, second, first, mds_spec(0)), 0);
    ASSERT_EQ(
        target_export(*queue, second, (dir.path() / "second.img").string()), 0
    );
    EXPECT_EQ(read_file(dir.path() / "second.img"), data);

    EXPECT_EQ(target_remove(*queue, first), 0);
    EXPECT_EQ(target_remove(*queue, second), 0);
}

// The object may be larger than the file; the tail reads back as zero.
TEST(ImageTest, larger_size_pads_with_zeros) {
    rawstor::tests::ObjectEnv env(8922, 8923);
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    std::string data = pattern(chunk_size);
    write_file(dir.path() / "in.img", data);
    std::string target =
        object_target(env, "018f4e2a-4000-7000-8000-000000000003");

    ASSERT_EQ(
        target_create_from_file(
            *queue, target, (dir.path() / "in.img").string(),
            mds_spec(2 * chunk_size)
        ),
        0
    );
    ASSERT_EQ(
        target_export(*queue, target, (dir.path() / "out.img").string()), 0
    );
    EXPECT_EQ(
        read_file(dir.path() / "out.img"), data + std::string(chunk_size, '\0')
    );

    EXPECT_EQ(target_remove(*queue, target), 0);
}

TEST(ImageTest, smaller_size_is_einval_and_creates_nothing) {
    rawstor::tests::ObjectEnv env(8924, 8925);
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    write_file(dir.path() / "in.img", pattern(2 * chunk_size));
    std::string target =
        object_target(env, "018f4e2a-4000-7000-8000-000000000004");

    EXPECT_EQ(
        target_create_from_file(
            *queue, target, (dir.path() / "in.img").string(),
            mds_spec(chunk_size)
        ),
        -EINVAL
    );
    RawstorObjectSpec spec{};
    EXPECT_EQ(target_spec(*queue, target, &spec), -ENOENT);
}

TEST(ImageTest, missing_sources_fail_and_create_nothing) {
    rawstor::tests::ObjectEnv env(8926, 8927);
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    std::string absent =
        object_target(env, "018f4e2a-4000-7000-8000-000000000005");
    std::string target =
        object_target(env, "018f4e2a-4000-7000-8000-000000000006");
    RawstorObjectSpec spec{};

    EXPECT_EQ(
        target_create_from_file(
            *queue, target, (dir.path() / "absent.img").string(), mds_spec(0)
        ),
        -ENOENT
    );
    EXPECT_EQ(
        target_create_from_target(*queue, target, absent, mds_spec(0)), -ENOENT
    );
    EXPECT_EQ(target_spec(*queue, target, &spec), -ENOENT);
    EXPECT_EQ(
        target_export(*queue, absent, (dir.path() / "out.img").string()),
        -ENOENT
    );
}

// A copy that fails once the new object exists removes it again: the source
// reports more data than its file holds, so reading the second block fails
// after the destination was created and half filled.
TEST(ImageTest, a_failed_copy_removes_the_new_object) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    write_file(dir.path() / "in.img", pattern(3 << 20));
    std::string source_id = "018f4e2a-4000-7000-8000-000000000007";
    std::string target_id = "018f4e2a-4000-7000-8000-000000000008";
    std::string source = "file://" + dir.path().string() + "/" + source_id;
    std::string target = "file://" + dir.path().string() + "/" + target_id;
    RawstorObjectSpec spec{};
    spec.width = 1;
    ASSERT_EQ(
        target_create_from_file(
            *queue, source, (dir.path() / "in.img").string(), spec
        ),
        0
    );
    std::filesystem::resize_file(
        dir.path() / source_id / "0" / "data", 1 << 20
    );

    std::vector<ssize_t> calls;
    EXPECT_LT(
        target_create_from_target(*queue, target, source, spec, &calls), 0
    );
    EXPECT_LT(calls.back(), 0);
    EXPECT_FALSE(std::filesystem::exists(dir.path() / target_id));

    EXPECT_EQ(target_remove(*queue, source), 0);
}

// A size left to the source is rounded up to the chunk size: an mds:// object
// is whole chunks, and a file rarely is.
TEST(ImageTest, a_size_left_to_the_source_is_rounded_up_to_the_chunk_size) {
    rawstor::tests::ObjectEnv env(8928, 8929);
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    std::string data = pattern(chunk_size + chunk_size / 2);
    write_file(dir.path() / "in.img", data);
    std::string target =
        object_target(env, "018f4e2a-4000-7000-8000-000000000009");

    ASSERT_EQ(
        target_create_from_file(
            *queue, target, (dir.path() / "in.img").string(), mds_spec(0)
        ),
        0
    );
    RawstorObjectSpec spec{};
    ASSERT_EQ(target_spec(*queue, target, &spec), 0);
    EXPECT_EQ(spec.size, 2 * chunk_size);

    ASSERT_EQ(
        target_export(*queue, target, (dir.path() / "out.img").string()), 0
    );
    EXPECT_EQ(
        read_file(dir.path() / "out.img"),
        data + std::string(chunk_size / 2, '\0')
    );

    EXPECT_EQ(target_remove(*queue, target), 0);
}
