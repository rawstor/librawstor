#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>

#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <fstream>

namespace {

TEST(FileLifecycleTest, create_spec_remove) {
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

    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

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

TEST(OstLifecycleTest, create_spec_remove) {
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    RawstorOSTFrameMetaBody meta_body = {
        .obj_id = {},
        .size = 1ull << 20,
        .epoch = 7,
        .sync_id = 0x1122334455667788ull,
        .sync_id_history = {0xaabbccddeeff0011ull, 0, 0, 0},
        .state = RAWSTOR_OBJECT_STATE_DIRTY,
    };

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, meta_body);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, meta_body);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_set_state(RAWSTOR_MAGIC, 0, 0);
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

    {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

} // unnamed namespace
