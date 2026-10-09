#include "opts.h"
#include "server.hpp"
#include "session.hpp"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

/*
 * The requests of a chunk's configuration register (docs/multiattach.md,
 * "The register"): SYNC_PREPARE/SYNC_ACCEPT against one member, reached
 * through Target as rawstor_target_sync_prepare()/_accept() reach it.
 */

namespace {

template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

void run(rawio::Queue& q, rawstd::Task<void> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    t.get();
}

RawstdUUID new_id() {
    RawstdUUID id;
    if (rawstd_uuid7_init(&id) != 0) {
        throw std::runtime_error("rawstd_uuid7_init() failed");
    }
    return id;
}

std::string id_string(const RawstdUUID& id) {
    RawstdUUIDString s;
    rawstd_uuid_to_string(&id, &s);
    return s;
}

} // namespace

// A file:// copy is a member of its own: the register requests act on its
// record directly, in this process.
TEST(RegisterTest, file_member_promises_and_accepts) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    RawstdUUID id = new_id();
    rawstor::Target target(
        {rawstd::URI(rawstd::URI(dir.uri()), id_string(id))}
    );
    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    run(*queue, target.create(*queue, spec));

    rawstor::Backend::SyncReply reply =
        run(*queue, target.sync_prepare(*queue, 0, 0, {4, 1}));
    EXPECT_TRUE(reply.ok);
    EXPECT_EQ(reply.meta.promised.counter, 4u);

    reply = run(*queue, target.sync_prepare(*queue, 0, 0, {3, 9}));
    EXPECT_FALSE(reply.ok);
    EXPECT_EQ(reply.meta.promised.counter, 4u);
    EXPECT_EQ(reply.meta.promised.proposer, 1u);

    RawstorObjectConfig config{};
    config.epoch = 9;
    config.sync_id = 0x99;
    config.resync_owner = 1;
    config.nroles = 2;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    config.roles[1] = RAWSTOR_OBJECT_MEMBER_SYNCING;
    reply =
        run(*queue,
            target.sync_accept(*queue, 0, 0, {4, 1}, {5, 1}, config, 0, 0));
    EXPECT_TRUE(reply.ok);

    // What the member persisted, read back the ordinary way.
    RawstorObjectMeta meta = run(*queue, target.meta(*queue, 0)).front();
    EXPECT_EQ(meta.config.epoch, 9u);
    EXPECT_EQ(meta.config.sync_id, 0x99u);
    EXPECT_EQ(meta.config.resync_owner, 1u);
    EXPECT_EQ(meta.accepted.counter, 4u);
    EXPECT_EQ(meta.promised.counter, 5u);
    ASSERT_EQ(meta.config.nroles, 2);
    EXPECT_EQ(meta.config.roles[1], RAWSTOR_OBJECT_MEMBER_SYNCING);
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);

    // A configuration set outside the register keeps the ballots: an old
    // ballot is still refused afterwards.
    config.epoch = 10;
    run(*queue, target.set_member_config(*queue, 0, 0, config, 0));
    meta = run(*queue, target.meta(*queue, 0)).front();
    EXPECT_EQ(meta.config.epoch, 10u);
    EXPECT_EQ(meta.promised.counter, 5u);
    EXPECT_EQ(meta.accepted.counter, 4u);
    EXPECT_FALSE(run(*queue, target.sync_prepare(*queue, 0, 0, {4, 9})).ok);
}

// An ost:// member: the request goes out as SYNC_ACCEPT with every field
// of the value, and the member's reply -- here a refusal -- comes back
// with its record.
TEST(RegisterTest, ost_member_request_and_reply) {
    rawstor::tests::Server server(8753, 256);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    RawstdUUID id = new_id();
    rawstor::Target target(
        {rawstd::URI(rawstd::URI("ost://127.0.0.1:8753"), id_string(id))}
    );

    // Accepts the connection the request below opens; left open for the
    // whole test.
    rawstor::tests::Session session(server);

    RawstorFrameSyncPropose seen{};
    std::atomic<bool> got{false};
    server.read(
        "SYNC_ACCEPT <<<", sizeof(RawstorFrameSyncPropose),
        [&seen, &got](const void* buf) {
            memcpy(&seen, buf, sizeof(seen));
            got = true;
        }
    );

    RawstorObjectConfig config{};
    config.epoch = 3;
    config.sync_id = 0x33;
    config.sync_id_history[0] = 0x22;
    config.resync_owner = 0x77;
    config.nroles = 3;
    config.roles[2] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    rawstd::Task<rawstor::Backend::SyncReply> task = target.sync_accept(
        *queue, 0, 0, {5, 0x77}, {6, 0x77}, config, RAWSTOR_SYNC_ALONE, 2
    );

    for (int i = 0; i < 5000 && !got; ++i) {
        try {
            queue->wait_timeout(1);
        } catch (const std::exception&) {
        }
    }
    ASSERT_TRUE(got);
    EXPECT_EQ(seen.head.cmd, RAWSTOR_CMD_SYNC_ACCEPT);
    EXPECT_EQ(memcmp(seen.payload.object_id, id.bytes, sizeof(id.bytes)), 0);
    EXPECT_EQ(seen.payload.ballot.counter, 5u);
    EXPECT_EQ(seen.payload.next.counter, 6u);
    EXPECT_EQ(seen.payload.config.epoch, 3u);
    EXPECT_EQ(seen.payload.config.sync_id_history[0], 0x22u);
    EXPECT_EQ(seen.payload.config.resync_owner, 0x77u);
    EXPECT_EQ(seen.payload.flags, RAWSTOR_SYNC_FLAG_ALONE);
    EXPECT_EQ(seen.payload.sessions, 2u);
    ASSERT_EQ(seen.payload.config.nroles, 3);
    EXPECT_EQ(seen.payload.config.roles[2], RAWSTOR_OBJECT_MEMBER_EXCLUDED);

    struct {
        RawstorFrameResponse response;
        RawstorFrameSyncReplyPayload reply;
    } __attribute__((packed)) out{};
    out.response.head = {
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_SYNC_ACCEPT,
        .cid = seen.head.cid,
    };
    out.response.body.res = static_cast<int32_t>(sizeof(out.reply));
    out.reply.ok = 0;
    out.reply.meta.width = 3;
    out.reply.meta.writers = 4;
    out.reply.meta.config.epoch = 8;
    out.reply.meta.config.nroles = 3;
    out.reply.meta.config.roles[0] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    out.reply.meta.promised = {9, 0x11};
    out.reply.meta.accepted = {8, 0x11};
    server.write("SYNC_ACCEPT >>>", &out, sizeof(out));

    rawstor::Backend::SyncReply reply = run(*queue, std::move(task));
    EXPECT_FALSE(reply.ok);
    EXPECT_EQ(reply.meta.config.epoch, 8u);
    EXPECT_EQ(reply.meta.writers, 4u);
    EXPECT_EQ(reply.meta.promised.counter, 9u);
    EXPECT_EQ(reply.meta.accepted.proposer, 0x11u);
    ASSERT_EQ(reply.meta.config.nroles, 3);
    EXPECT_EQ(reply.meta.config.roles[0], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
}
