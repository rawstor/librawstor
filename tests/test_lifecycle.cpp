#include "server.hpp"
#include "session.hpp"
#include "tmp_dir.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {

TEST(FileLifecycleTest, create_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000001";
    std::string target = rawstd::URI(location_uri, uuid).str();

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    int res = rawstor_object_create(target.c_str(), &spec);
    EXPECT_EQ(res, 0);

    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor_object_list(location.c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            EXPECT_EQ(target, *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_default_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string target(65536, '\0');

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    int res = rawstor_object_create_at(
        location.c_str(), nullptr, &spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);

    RawstorObjectSpec read_spec = {};
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor_object_list(location.c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            EXPECT_EQ(target, *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, meta_set_state) {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
                                 "test_objects" /
                                 "00000000-0000-7000-8000-000000000000";
    std::ostringstream oss;
    oss << "file://" << path.string();
    std::string target = oss.str();

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    int res = rawstor_object_create(target.c_str(), &spec);
    EXPECT_EQ(res, 0);

    RawstorObjectMeta meta{};
    res = rawstor_object_meta(target.c_str(), &meta);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(meta.size, 1ull << 20);
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(meta.epoch, 0u);
    EXPECT_EQ(meta.sync_id, 0u);
    for (size_t i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; ++i) {
        EXPECT_EQ(meta.sync_id_history[i], 0u);
    }

    RawstorObjectMeta next{};
    next.size = 42; /* must be ignored */
    next.epoch = 3;
    next.sync_id = 0x1122334455667788ull;
    next.sync_id_history[0] = 0xaabbccddeeff0011ull;
    next.state = RAWSTOR_OBJECT_STATE_DIRTY;
    res = rawstor_object_set_state(target.c_str(), &next);
    EXPECT_EQ(res, 0);

    res = rawstor_object_meta(target.c_str(), &meta);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(meta.size, 1ull << 20);
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_STATE_DIRTY);
    EXPECT_EQ(meta.epoch, 3u);
    EXPECT_EQ(meta.sync_id, 0x1122334455667788ull);
    EXPECT_EQ(meta.sync_id_history[0], 0xaabbccddeeff0011ull);
    EXPECT_EQ(meta.sync_id_history[1], 0u);

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000002";
    std::string target(65536, '\0');

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    int res = rawstor_object_create_at(
        location.c_str(), uuid.c_str(), &spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);
    EXPECT_EQ(target, rawstd::URI(location_uri, uuid).str());

    RawstorObjectSpec read_spec = {};
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor_object_list(location.c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            EXPECT_EQ(target, *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, chunk_identity_roundtrip) {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
                                 "test_objects" /
                                 "00000000-0000-7000-8000-00000000c001";
    std::ostringstream oss;
    oss << "file://" << path.string();
    std::string target = oss.str();

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    spec.member_kind = RAWSTOR_MEMBER_DATA;
    spec.width = 2;
    spec.chunk_size = 1ull << 20;
    spec.logical_index = 7;
    spec.snap_version = 0;
    memset(spec.volume_id, 0xab, sizeof(spec.volume_id));

    int res = rawstor_object_create(target.c_str(), &spec);
    ASSERT_EQ(res, 0);

    RawstorObjectMeta meta{};
    res = rawstor_object_meta(target.c_str(), &meta);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(meta.member_kind, RAWSTOR_MEMBER_DATA);
    EXPECT_EQ(meta.width, 2u);
    EXPECT_EQ(meta.logical_index, 7u);
    EXPECT_EQ(meta.chunk_size, 1ull << 20);
    EXPECT_EQ(meta.snap_version, 0u);
    for (size_t i = 0; i < sizeof(meta.volume_id); ++i) {
        EXPECT_EQ(meta.volume_id[i], 0xab);
    }

    /* set_state must never change the identity: the stored values win. */
    RawstorObjectMeta next{};
    next.epoch = 1;
    next.sync_id = 0x1111111111111111ull;
    next.state = RAWSTOR_OBJECT_STATE_DIRTY;
    next.logical_index = 999; /* must be ignored */
    next.chunk_size = 4096;   /* must be ignored */
    res = rawstor_object_set_state(target.c_str(), &next);
    EXPECT_EQ(res, 0);

    res = rawstor_object_meta(target.c_str(), &meta);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_STATE_DIRTY);
    EXPECT_EQ(meta.epoch, 1u);
    EXPECT_EQ(meta.logical_index, 7u);
    EXPECT_EQ(meta.chunk_size, 1ull << 20);
    EXPECT_EQ(meta.width, 2u);
    for (size_t i = 0; i < sizeof(meta.volume_id); ++i) {
        EXPECT_EQ(meta.volume_id[i], 0xab);
    }

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, list_chunks) {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "test_objects_list";
    std::filesystem::remove_all(dir);

    std::string location = "file://" + dir.string();

    /* A location that was never written to lists as empty. */
    RawstorObjectListEntry* entries = nullptr;
    size_t nentries = 42;
    int res = rawstor_object_list_chunks(location.c_str(), &entries, &nentries);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(nentries, 0u);
    EXPECT_EQ(entries, nullptr);

    const char* uuids[2] = {
        "00000000-0000-7000-8000-00000000d001",
        "00000000-0000-7000-8000-00000000d002",
    };
    for (size_t i = 0; i < 2; ++i) {
        RawstorObjectSpec spec{};
        spec.size = 1ull << 20;
        spec.width = 2;
        spec.chunk_size = 1ull << 20;
        spec.logical_index = i;
        memset(spec.volume_id, 0xab, sizeof(spec.volume_id));
        std::string target = location + "/" + uuids[i];
        ASSERT_EQ(rawstor_object_create(target.c_str(), &spec), 0);
    }

    /* Foreign and torn files must be skipped, not fail the scan. */
    std::ofstream(dir / "not-an-object.spec") << "garbage";
    std::ofstream(dir / "README") << "text";

    res = rawstor_object_list_chunks(location.c_str(), &entries, &nentries);
    EXPECT_EQ(res, 0);
    ASSERT_EQ(nentries, 2u);
    ASSERT_NE(entries, nullptr);

    bool seen[2] = {false, false};
    for (size_t i = 0; i < nentries; ++i) {
        EXPECT_EQ(entries[i].meta.size, 1ull << 20);
        EXPECT_EQ(entries[i].meta.width, 2u);
        EXPECT_EQ(entries[i].meta.chunk_size, 1ull << 20);
        for (size_t j = 0; j < sizeof(entries[i].meta.volume_id); ++j) {
            EXPECT_EQ(entries[i].meta.volume_id[j], 0xab);
        }
        ASSERT_LT(entries[i].meta.logical_index, 2u);
        seen[entries[i].meta.logical_index] = true;
    }
    EXPECT_TRUE(seen[0]);
    EXPECT_TRUE(seen[1]);

    free(entries);
    std::filesystem::remove_all(dir);
}

TEST(OstLifecycleTest, create_spec_list_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string uuid = "00000000-0000-7000-8000-000000000003";
    std::string target = rawstd::URI(location_uri, uuid).str();

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        RawstorObjectSpec expected{};
        expected.size = 1ull << 20;
        s.cmd_spec(RAWSTOR_MAGIC, 0, expected);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    {
        RawstorObjectSpec spec{};
        spec.size = 1ull << 20;

        int res = rawstor_object_create(target.c_str(), &spec);
        EXPECT_EQ(res, 0);
    }

    {
        RawstorObjectSpec read_spec;
        int res = rawstor_object_spec(target.c_str(), &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

TEST(OstLifecycleTest, create_at_default_spec_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string location = location_uri.str();
    std::string target(65536, '\0');

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        RawstorObjectSpec expected{};
        expected.size = 1ull << 20;
        s.cmd_spec(RAWSTOR_MAGIC, 0, expected);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    {
        RawstorObjectSpec spec{};
        spec.size = 1ull << 20;

        int res = rawstor_object_create_at(
            location.c_str(), nullptr, &spec, target.data(), target.size()
        );
        ASSERT_GT(res, 0);
        ASSERT_LT((size_t)res, target.size());
        target.resize(res);
    }

    {
        RawstorObjectSpec read_spec = {};
        int res = rawstor_object_spec(target.c_str(), &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

TEST(OstLifecycleTest, create_at_spec_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000004";
    std::string target(65536, '\0');

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        RawstorObjectSpec expected{};
        expected.size = 1ull << 20;
        s.cmd_spec(RAWSTOR_MAGIC, 0, expected);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    {
        RawstorObjectSpec spec{};
        spec.size = 1ull << 20;

        int res = rawstor_object_create_at(
            location.c_str(), uuid.c_str(), &spec, target.data(), target.size()
        );
        ASSERT_GT(res, 0);
        ASSERT_LT((size_t)res, target.size());
        target.resize(res);
        EXPECT_EQ(target, rawstd::URI(location_uri, uuid).str());
    }

    {
        RawstorObjectSpec read_spec = {};
        int res = rawstor_object_spec(target.c_str(), &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

TEST(OstLifecycleTest, meta_set_state) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string uuid = "00000000-0000-7000-8000-000000000005";
    std::string target = rawstd::URI(location_uri, uuid).str();

    RawstorOSTFrameMetaBody meta_body{};
    meta_body.size = 1ull << 20;
    meta_body.epoch = 7;
    meta_body.sync_id = 0x1122334455667788ull;
    meta_body.sync_id_history[0] = 0xaabbccddeeff0011ull;
    meta_body.state = RAWSTOR_OBJECT_STATE_DIRTY;

    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, meta_body);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_state(RAWSTOR_MAGIC, 0, 0);
    }

    {
        RawstorObjectMeta meta{};
        int res = rawstor_object_meta(target.c_str(), &meta);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(meta.size, 1ull << 20);
        EXPECT_EQ(meta.epoch, 7u);
        EXPECT_EQ(meta.sync_id, 0x1122334455667788ull);
        EXPECT_EQ(meta.sync_id_history[0], 0xaabbccddeeff0011ull);
        EXPECT_EQ(meta.state, RAWSTOR_OBJECT_STATE_DIRTY);
    }

    {
        RawstorObjectMeta meta{};
        meta.epoch = 8;
        meta.sync_id = 0x99ull;
        meta.state = RAWSTOR_OBJECT_STATE_CLEAN;
        int res = rawstor_object_set_state(target.c_str(), &meta);
        EXPECT_EQ(res, 0);
    }
}

TEST(FileLifecycleTest, snapshot_not_supported) {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
                                 "test_objects" /
                                 "00000000-0000-7000-8000-00000000e001";
    std::string target = "file://" + path.string();

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(target.c_str(), &spec), 0);

    /* No CoW on plain files: never a hidden fallback copy. */
    EXPECT_EQ(rawstor_object_snapshot(target.c_str(), 1), -ENOTSUP);
    EXPECT_EQ(rawstor_object_snap_remove(target.c_str(), 1), -ENOTSUP);

    /* 0 is the live version, not a snapshot. */
    EXPECT_EQ(rawstor_object_snapshot(target.c_str(), 0), -EINVAL);
    EXPECT_EQ(rawstor_object_snap_remove(target.c_str(), 0), -EINVAL);

    EXPECT_EQ(rawstor_object_remove(target.c_str()), 0);
}

TEST(OstLifecycleTest, snapshot) {
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_snapshot(RAWSTOR_CMD_SNAPSHOT, RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_snapshot(RAWSTOR_CMD_SNAPSHOT, RAWSTOR_MAGIC, 0, -ENOTSUP);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_snapshot(RAWSTOR_CMD_SNAP_REMOVE, RAWSTOR_MAGIC, 0, 0);
    }

    EXPECT_EQ(rawstor_object_snapshot(target.c_str(), 7), 0);
    EXPECT_EQ(rawstor_object_snapshot(target.c_str(), 7), -ENOTSUP);
    EXPECT_EQ(rawstor_object_snap_remove(target.c_str(), 7), 0);
}

TEST(OstLifecycleTest, list) {
    rawstor::tests::Server server(8753, 256);
    std::string location = "ost://127.0.0.1:8753";

    std::vector<RawstorOSTFrameMetaBody> records(2);
    for (size_t i = 0; i < records.size(); ++i) {
        RawstorOSTFrameMetaBody& r = records[i];
        r = {};
        memset(r.obj_id, 0x10 + i, sizeof(r.obj_id));
        r.size = 1ull << 20;
        r.state = RAWSTOR_OBJECT_STATE_CLEAN;
        r.member_kind = RAWSTOR_MEMBER_DATA;
        r.width = 2;
        memset(r.volume_id, 0xab, sizeof(r.volume_id));
        r.logical_index = i;
        r.chunk_size = 1ull << 20;
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_list(
            RAWSTOR_MAGIC, 0, static_cast<int32_t>(records.size()), records
        );
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_list(RAWSTOR_MAGIC, 0, 0, {});
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_list(RAWSTOR_MAGIC, 0, -EIO, {});
    }

    {
        RawstorObjectListEntry* entries = nullptr;
        size_t nentries = 0;
        int res =
            rawstor_object_list_chunks(location.c_str(), &entries, &nentries);
        EXPECT_EQ(res, 0);
        ASSERT_EQ(nentries, 2u);
        ASSERT_NE(entries, nullptr);
        for (size_t i = 0; i < nentries; ++i) {
            EXPECT_EQ(entries[i].obj_id[0], 0x10 + i);
            EXPECT_EQ(entries[i].meta.size, 1ull << 20);
            EXPECT_EQ(entries[i].meta.width, 2u);
            EXPECT_EQ(entries[i].meta.logical_index, i);
            EXPECT_EQ(entries[i].meta.chunk_size, 1ull << 20);
        }
        free(entries);
    }

    {
        RawstorObjectListEntry* entries = nullptr;
        size_t nentries = 42;
        int res =
            rawstor_object_list_chunks(location.c_str(), &entries, &nentries);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(nentries, 0u);
        EXPECT_EQ(entries, nullptr);
    }

    {
        RawstorObjectListEntry* entries = nullptr;
        size_t nentries = 0;
        int res =
            rawstor_object_list_chunks(location.c_str(), &entries, &nentries);
        EXPECT_EQ(res, -EIO);
    }
}

} // unnamed namespace
