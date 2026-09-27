#include "server.hpp"
#include "session.hpp"
#include "tmp_dir.hpp"

#include "opts.h"
#include "rawio_sync.hpp"
#include "slot.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

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

TEST(ListTest, empty) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    ssize_t res =
        rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_location_list(
                queue.get(), location.str().c_str(), 0, &targets, &token, cb,
                data
            );
        });
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(0));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_EQ(it, nullptr);

        rawstor_string_list_delete(targets);
    }
    EXPECT_TRUE(rawstor_pagination_token_empty(&token));
}

TEST(ListTest, merge) {
    rawstor::tests::TmpDir dir1;
    rawstor::tests::TmpDir dir2;
    rawstd::URI location1(dir1.uri());
    rawstd::URI location2(dir2.uri());

    rawstd::URI target11 =
        rawstd::URI(location1, "00000000-0000-7000-8000-000000000001");
    rawstd::URI target12 =
        rawstd::URI(location1, "00000000-0000-7000-8000-000000000002");
    rawstd::URI target22 =
        rawstd::URI(location2, "00000000-0000-7000-8000-000000000002");
    rawstd::URI target23 =
        rawstd::URI(location2, "00000000-0000-7000-8000-000000000003");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
    auto create = [&](const rawstd::URI& target,
                      const RawstorObjectSpec& spec) {
        return rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_target_create(
                queue.get(), target.str().c_str(), &spec, cb, data
            );
        });
    };

    ssize_t res;
    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
    };
    res = create(target11, spec);
    ASSERT_EQ(res, 0);
    res = create(target12, spec);
    ASSERT_EQ(res, 0);
    res = create(target22, spec);
    ASSERT_EQ(res, 0);
    res = create(target23, spec);
    ASSERT_EQ(res, 0);

    std::string locations = rawstd::URI::uris({location1, location2});

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
        return rawstor_location_list(
            queue.get(), locations.c_str(), 0, &targets, &token, cb, data
        );
    });
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(3));

        if (rawstor_string_list_size(targets) == 3) {
            // Location::list() always stamps an explicit offset segment,
            // even "0" -- unlike target1N/target2N's own bare, offset-less
            // form above.
            const char** it = rawstor_string_list_iter(targets);
            EXPECT_NE(it, nullptr);
            EXPECT_EQ(rawstd::URI::uris({rawstd::URI(target11, "0")}), *it);

            it = rawstor_string_list_next(it);
            EXPECT_NE(it, nullptr);
            EXPECT_EQ(
                rawstd::URI::uris(
                    {rawstd::URI(target12, "0"), rawstd::URI(target22, "0")}
                ),
                *it
            );

            it = rawstor_string_list_next(it);
            EXPECT_NE(it, nullptr);
            EXPECT_EQ(rawstd::URI::uris({rawstd::URI(target23, "0")}), *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_TRUE(rawstor_pagination_token_empty(&token));

    auto remove = [&](const rawstd::URI& target) {
        return rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_target_remove(
                queue.get(), target.str().c_str(), cb, data
            );
        });
    };
    res = remove(target11);
    EXPECT_EQ(res, 0);
    res = remove(target12);
    EXPECT_EQ(res, 0);
    res = remove(target22);
    EXPECT_EQ(res, 0);
    res = remove(target23);
    EXPECT_EQ(res, 0);
}

// Two locations each holding a different offset of the *same* id: they
// must merge into one Target listing both chunk URIs (offset-ascending),
// not two separate single-chunk Targets -- Backend::list_chunks() groups
// by id alone (its own ChunkGroup, src/backend.hpp) precisely so
// Location::list() never has to split a multi-chunk object's own chunks
// across the ids/offsets a plain uuid map used to key on.
TEST(ListTest, merge_multi_chunk) {
    rawstor::tests::TmpDir dir1;
    rawstor::tests::TmpDir dir2;
    rawstd::URI location1(dir1.uri());
    rawstd::URI location2(dir2.uri());

    std::string uuid_string = "00000000-0000-7000-8000-000000000001";
    uint64_t offset = 1ull << 30;
    char offset_hex[17];
    snprintf(offset_hex, sizeof(offset_hex), "%" PRIx64, offset);

    rawstd::URI chunk0(rawstd::URI(location1, uuid_string), "0");
    rawstd::URI chunk1(rawstd::URI(location2, uuid_string), offset_hex);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
    auto create = [&](const rawstd::URI& target,
                      const RawstorObjectSpec& spec) {
        return rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_target_create(
                queue.get(), target.str().c_str(), &spec, cb, data
            );
        });
    };

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
    };
    ssize_t res = create(chunk0, spec);
    ASSERT_EQ(res, 0);
    res = create(chunk1, spec);
    ASSERT_EQ(res, 0);

    std::string locations = rawstd::URI::uris({location1, location2});

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
        return rawstor_location_list(
            queue.get(), locations.c_str(), 0, &targets, &token, cb, data
        );
    });
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        if (rawstor_string_list_size(targets) == 1) {
            const char** it = rawstor_string_list_iter(targets);
            EXPECT_NE(it, nullptr);
            if (it != nullptr) {
                // Location::list() always stamps an explicit offset
                // segment, even "0" -- unlike a caller-typed target
                // string, which may omit it (TargetPath's own doc
                // comment, target.hpp).
                EXPECT_EQ(rawstd::URI::uris({chunk0, chunk1}), *it);
            }

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_TRUE(rawstor_pagination_token_empty(&token));

    auto remove = [&](const rawstd::URI& target) {
        return rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_target_remove(
                queue.get(), target.str().c_str(), cb, data
            );
        });
    };
    res = remove(chunk0);
    EXPECT_EQ(res, 0);
    res = remove(chunk1);
    EXPECT_EQ(res, 0);
}

TEST(ListTest, pagination) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    auto list = [&](RawstorStringList** page, RawstorPaginationToken* token) {
        return rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_location_list(
                queue.get(), location.str().c_str(), 0, page, token, cb, data
            );
        });
    };

    {
        RawstorStringList* page;
        RawstorPaginationToken token = {};
        ssize_t res = list(&page, &token);
        EXPECT_EQ(res, 0);
        if (res == 0) {
            EXPECT_EQ(rawstor_string_list_size(page), static_cast<size_t>(0));
            EXPECT_TRUE(rawstor_pagination_token_empty(&token));

            rawstor_string_list_delete(page);
        }
    }

    unsigned int total = rawstor_opts_list_limit() + 1;

    std::vector<std::string> targets;
    targets.reserve(total);
    for (unsigned int i = 0; i < total; ++i) {
        RawstorObjectSpec spec{
            .size = 1ull << 10,
            .width = 1,
            .chunk_size = 0,
        };

        char target[65536];
        ssize_t res =
            rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
                return rawstor_location_create(
                    queue.get(), location.str().c_str(), nullptr, &spec, target,
                    sizeof(target), cb, data
                );
            });
        EXPECT_GT(res, 0);

        // Location::list() always stamps an explicit offset segment,
        // even "0" -- unlike rawstor_location_create()'s own bare,
        // offset-less return value here.
        targets.push_back(std::string(target) + "/0");
    }
    std::sort(targets.begin(), targets.end());

    RawstorStringList* page;
    RawstorPaginationToken token = {};
    ssize_t res = list(&page, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(
            rawstor_string_list_size(page),
            static_cast<size_t>(rawstor_opts_list_limit())
        );

        size_t i = 0;
        for (const char** it = rawstor_string_list_iter(page); it != NULL;
             it = rawstor_string_list_next(it), ++i) {
            EXPECT_LT(i, targets.size());
            if (i < targets.size()) {
                EXPECT_EQ(*it, targets[i]);
            }
        }

        rawstor_string_list_delete(page);

        EXPECT_FALSE(rawstor_pagination_token_empty(&token));
        if (!rawstor_pagination_token_empty(&token)) {
            ssize_t res = list(&page, &token);
            EXPECT_EQ(res, 0);
            if (res == 0) {
                EXPECT_EQ(
                    rawstor_string_list_size(page), static_cast<size_t>(1)
                );

                const char** it = rawstor_string_list_iter(page);
                EXPECT_NE(it, nullptr);
                if (it != nullptr) {
                    EXPECT_EQ(*it, targets.back());
                }

                it = rawstor_string_list_next(it);
                EXPECT_EQ(it, nullptr);

                rawstor_string_list_delete(page);

                EXPECT_TRUE(rawstor_pagination_token_empty(&token));
            }
        }
    }

    for (const auto& target : targets) {
        ssize_t res =
            rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
                return rawstor_target_remove(
                    queue.get(), target.c_str(), cb, data
                );
            });
        EXPECT_EQ(res, 0);
    }
}

// Location::list()/create() and Target::create()/remove()/spec() all use
// a Slot::create()-only, never-open()-ed Slot for their
// metadata work -- unlike a data-path Slot, _id stays unset on
// one of these for its whole lifetime. invalidate_backend()'s reconnect
// path used to call the replacement backend's set_object(*_id)
// unconditionally regardless -- dereferencing an unset
// std::optional<RawstdUUID> the very first time a metadata op actually
// needed to reconnect a backend, not something any of ListTest's other
// cases above exercise (they never fail an op in the first place).
TEST(ListTest, invalidate_backend_on_metadata_only_connection) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    std::unique_ptr<rawstor::Slot> slot =
        run(*queue, rawstor::Slot::create(*queue, location, 1));
    std::shared_ptr<rawstor::Backend> be = slot->get_next_backend();

    EXPECT_NO_THROW(run(*queue, slot->invalidate_backend(be)));
}

} // unnamed namespace
