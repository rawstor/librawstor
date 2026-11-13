#include "object.hpp"
#include "object_env.hpp"
#include "opts.h"
#include "owner.hpp"
#include "slot.hpp"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>

/*
 * A writer that replaces a broken connection is still the same writer
 * (docs/mirroring.md, "DIRTY, CLEAN and LOST"). When the server is the one
 * to end the connection, it retires the session before the replacement has
 * opened; the copy must not be LOST for that.
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

// Forwards a client's connections to a server and can end them in the order
// a protocol error does: the server's side first, the client's side only
// after the server had time to retire the session.
class SeveringProxy {
private:
    struct Pair {
        int client;
        int upstream;
    };

    int _listen_fd;
    int _wake_read;
    int _wake_write;
    unsigned int _upstream_port;
    std::thread _thread;
    std::mutex _mutex;
    std::condition_variable _cv;
    bool _severed = false;

    static void _close_side(std::vector<Pair>& pairs, bool upstream) {
        for (Pair& p : pairs) {
            int& fd = upstream ? p.upstream : p.client;
            if (fd != -1) {
                ::close(fd);
                fd = -1;
            }
        }
    }

    void _accept(std::vector<Pair>& pairs) {
        int client = ::accept(_listen_fd, nullptr, nullptr);
        int upstream = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(_upstream_port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (client >= 0 &&
            ::connect(
                upstream, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
            ) == 0) {
            pairs.push_back({client, upstream});
            return;
        }
        if (client >= 0) {
            ::close(client);
        }
        ::close(upstream);
    }

    // Moves what one side has to say to the other; false once either side
    // is gone.
    static bool _forward(int from, int to) {
        char buf[65536];
        ssize_t n = ::read(from, buf, sizeof(buf));
        if (n <= 0) {
            return false;
        }
        for (ssize_t sent = 0; sent < n;) {
            ssize_t w = ::send(to, buf + sent, n - sent, MSG_NOSIGNAL);
            if (w <= 0) {
                return false;
            }
            sent += w;
        }
        return true;
    }

    void _loop() {
        std::vector<Pair> pairs;
        for (;;) {
            std::vector<pollfd> fds{
                {_wake_read, POLLIN, 0}, {_listen_fd, POLLIN, 0}
            };
            for (const Pair& p : pairs) {
                fds.push_back({p.client, POLLIN, 0});
                fds.push_back({p.upstream, POLLIN, 0});
            }
            if (::poll(fds.data(), fds.size(), -1) < 0) {
                continue;
            }
            if (fds[0].revents & POLLIN) {
                char command;
                if (::read(_wake_read, &command, 1) != 1 || command != 's') {
                    break;
                }
                _close_side(pairs, true);
                std::this_thread::sleep_for(std::chrono::milliseconds(300));
                _close_side(pairs, false);
                pairs.clear();
                std::lock_guard<std::mutex> lock(_mutex);
                _severed = true;
                _cv.notify_all();
                continue;
            }
            // Only the pairs that were polled have events to look at; one
            // accepted now is polled on the next round.
            size_t polled = pairs.size();
            if (fds[1].revents & POLLIN) {
                _accept(pairs);
            }
            for (size_t i = 0; i < polled;) {
                const short client_events = fds[2 + 2 * i].revents;
                const short upstream_events = fds[3 + 2 * i].revents;
                bool alive = true;
                if (client_events & (POLLIN | POLLHUP)) {
                    alive = _forward(pairs[i].client, pairs[i].upstream);
                }
                if (alive && (upstream_events & (POLLIN | POLLHUP))) {
                    alive = _forward(pairs[i].upstream, pairs[i].client);
                }
                if (alive) {
                    ++i;
                    continue;
                }
                ::close(pairs[i].client);
                ::close(pairs[i].upstream);
                pairs.erase(pairs.begin() + i);
                fds.erase(fds.begin() + 2 + 2 * i, fds.begin() + 4 + 2 * i);
                --polled;
            }
        }
        _close_side(pairs, true);
        _close_side(pairs, false);
    }

public:
    SeveringProxy(unsigned int port, unsigned int upstream_port) :
        _upstream_port(upstream_port) {
        _listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(
                _listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
            ) != 0 ||
            ::listen(_listen_fd, 16) != 0) {
            throw std::runtime_error("proxy bind/listen failed");
        }
        int wake[2];
        if (::pipe(wake) != 0) {
            throw std::runtime_error("pipe() failed");
        }
        _wake_read = wake[0];
        _wake_write = wake[1];
        _thread = std::thread([this]() { _loop(); });
    }

    ~SeveringProxy() {
        char command = 'q';
        ssize_t ignored = ::write(_wake_write, &command, 1);
        (void)ignored;
        _thread.join();
        ::close(_listen_fd);
        ::close(_wake_read);
        ::close(_wake_write);
    }

    // Returns once the client's side of every connection is gone as well.
    void sever() {
        {
            std::lock_guard<std::mutex> lock(_mutex);
            _severed = false;
        }
        char command = 's';
        ssize_t ignored = ::write(_wake_write, &command, 1);
        (void)ignored;
        std::unique_lock<std::mutex> lock(_mutex);
        _cv.wait(lock, [this]() { return _severed; });
    }
};

void write_one(rawio::Queue& queue, rawstor::Object& object) {
    std::string data = "ping";
    run(queue, object.pwrite(data.data(), data.size(), 0, false));
}

} // namespace

// The writer is still there: it opens the replacement and replays what it
// had not seen acknowledged, so the copy it was writing is not LOST.
TEST(SessionReplaceTest, ost_session_replaced_after_server_drop_stays_dirty) {
    rawstor::tests::ObjectEnv env(8850, 8851);
    SeveringProxy proxy(8852, 8851);
    auto queue = rawio::Queue::create(64);
    const RawstdUUID id = new_id();
    rawstor::Target via_proxy(
        {rawstd::URI(rawstd::URI("ost://127.0.0.1:8852"), id_string(id))}
    );
    rawstor::Target direct(
        {rawstd::URI(rawstd::URI("ost://127.0.0.1:8851"), id_string(id))}
    );
    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    run(*queue, direct.create(*queue, spec));

    auto writer = run(*queue, via_proxy.open(*queue, 0));
    write_one(*queue, *writer);
    ASSERT_EQ(
        run(*queue, direct.meta(*queue)).front().state,
        RAWSTOR_OBJECT_SYNC_STATE_DIRTY
    );

    proxy.sever();
    write_one(*queue, *writer);

    RawstorObjectMeta meta = run(*queue, direct.meta(*queue)).front();
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(meta.writers, 1u);

    run(*queue, writer->close());
}

// Repeated drops of one writer each keep the copy DIRTY until the next
// replacement.
TEST(SessionReplaceTest, ost_replacement_dropped_in_turn_stays_dirty) {
    rawstor::tests::ObjectEnv env(8856, 8857);
    SeveringProxy proxy(8858, 8857);
    auto queue = rawio::Queue::create(64);
    const RawstdUUID id = new_id();
    rawstor::Target via_proxy(
        {rawstd::URI(rawstd::URI("ost://127.0.0.1:8858"), id_string(id))}
    );
    rawstor::Target direct(
        {rawstd::URI(rawstd::URI("ost://127.0.0.1:8857"), id_string(id))}
    );
    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    run(*queue, direct.create(*queue, spec));

    auto writer = run(*queue, via_proxy.open(*queue, 0));
    write_one(*queue, *writer);
    for (int drop = 0; drop < 3; ++drop) {
        proxy.sever();
        write_one(*queue, *writer);
    }

    RawstorObjectMeta meta = run(*queue, direct.meta(*queue)).front();
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(meta.writers, 1u);

    run(*queue, writer->close());
}

namespace {

// One step of a queue the test drives by hand: waits up to `ms` for an event.
void step(rawio::Queue& queue, unsigned int ms) {
    try {
        queue.wait_timeout(ms);
    } catch (const std::system_error& e) {
        if (e.code().value() != ETIME) {
            throw;
        }
    }
}

void pump(rawio::Queue& queue, unsigned int ms) {
    const auto end =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
        step(queue, 10);
    }
}

} // namespace

// The wait for a dropped writer's replacement ends once the replacement has
// taken over, and does nothing to the copy then: a later departure of the same
// writer is another wait's to end. Each side runs on its own queue and the
// first wait is not resumed until the replacement has dropped in turn.
TEST(SessionReplaceTest, adopted_departure_wait_leaves_the_next_departure) {
    rawstor::tests::TmpDir dir;
    auto first_queue = rawio::Queue::create(64);
    auto second_queue = rawio::Queue::create(64);
    const rawstd::URI location(dir.uri());
    const RawstdUUID id = new_id();
    const RawstdUUID session = new_id();
    const std::chrono::milliseconds grace(2000);
    const std::string data = "ping";

    auto first =
        run(*first_queue, rawstor::Slot::create(*first_queue, location));
    RawstorObjectSpec spec{};
    spec.size = 4096;
    spec.width = 1;
    run(*first_queue,
        first->create(
            id, 0, spec, RAWSTOR_MEMBER_DATA, rawstor::tests::default_owner()
        ));
    first->set_departure_grace(grace, nullptr);
    run(*first_queue, first->open(session, id, 0, 0, RawstdUUID{}));
    run(*first_queue, first->pwrite(data.data(), data.size(), 0, false, 0));
    rawstd::Task<void> first_close = first->close();
    pump(*first_queue, 100);
    ASSERT_FALSE(first_close.done());

    auto second =
        run(*second_queue, rawstor::Slot::create(*second_queue, location));
    second->set_departure_grace(grace, nullptr);
    run(*second_queue, second->open(session, id, 0, 0, RawstdUUID{}));
    run(*second_queue, second->pwrite(data.data(), data.size(), 0, false, 0));
    rawstd::Task<void> second_close = second->close();
    pump(*second_queue, 100);
    ASSERT_FALSE(second_close.done());

    // Only now does the first wait run: its replacement is gone, too.
    for (unsigned int i = 0; i < 100 && !first_close.done(); ++i) {
        step(*first_queue, 10);
    }
    ASSERT_TRUE(first_close.done());
    first_close.get();

    auto observer =
        run(*first_queue, rawstor::Slot::create(*first_queue, location));
    RawstorObjectMeta meta = run(*first_queue, observer->meta(id, 0)).front();
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(meta.writers, 1u);

    // The second departure is still waited for, and can still be taken over.
    auto third =
        run(*second_queue, rawstor::Slot::create(*second_queue, location));
    run(*second_queue, third->open(session, id, 0, 0, RawstdUUID{}));
    for (unsigned int i = 0; i < 100 && !second_close.done(); ++i) {
        step(*second_queue, 10);
    }
    ASSERT_TRUE(second_close.done());
    second_close.get();
    meta = run(*first_queue, observer->meta(id, 0)).front();
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(meta.writers, 1u);

    run(*second_queue, third->leave());
    run(*second_queue, third->close());
    meta = run(*first_queue, observer->meta(id, 0)).front();
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(meta.writers, 0u);
    run(*first_queue, observer->close());
}

// A writer that does not come back is not waited for forever: its writes
// are unaccounted for, and the copy is LOST once the wait is over.
TEST(SessionReplaceTest, ost_session_not_replaced_after_server_drop_is_lost) {
    rawstor::tests::ObjectEnv env(8853, 8854);
    SeveringProxy proxy(8855, 8854);
    auto queue = rawio::Queue::create(64);
    const RawstdUUID id = new_id();
    rawstor::Target via_proxy(
        {rawstd::URI(rawstd::URI("ost://127.0.0.1:8855"), id_string(id))}
    );
    rawstor::Target direct(
        {rawstd::URI(rawstd::URI("ost://127.0.0.1:8854"), id_string(id))}
    );
    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    run(*queue, direct.create(*queue, spec));

    auto writer = run(*queue, via_proxy.open(*queue, 0));
    write_one(*queue, *writer);
    proxy.sever();

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(10);
    RawstorObjectMeta meta = run(*queue, direct.meta(*queue)).front();
    while (meta.state != RAWSTOR_OBJECT_SYNC_STATE_LOST &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        meta = run(*queue, direct.meta(*queue)).front();
    }
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_LOST);
    EXPECT_EQ(meta.writers, 0u);

    run(*queue, writer->close(false));
}
