#include <mds/reconciler.hpp>

#include "opts.h"
#include "slot.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>

#include <cstring>
#include <exception>
#include <set>
#include <string>
#include <system_error>
#include <utility>

#include <unistd.h>

#include <cerrno>

namespace rawstor {
namespace mdsserver {

namespace {

// How many of each kind of difference are logged one by one.
constexpr size_t logged_members = 8;

using MemberKey = std::pair<std::string, uint64_t>;

MemberKey key_of(const RawstdUUID& id, uint64_t offset) {
    return {
        std::string(reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes)),
        offset
    };
}

std::set<MemberKey> keys_of(const std::vector<Member>& members) {
    std::set<MemberKey> ret;
    for (const Member& member : members) {
        ret.insert(key_of(member.id, member.offset));
    }
    return ret;
}

void log_members(
    const char* ost, const char* what, const std::set<MemberKey>& members
) {
    if (members.empty()) {
        return;
    }
    rawstd_warning("OST %s %s %zu member(s)\n", ost, what, members.size());
    size_t n = 0;
    for (const MemberKey& member : members) {
        if (n++ == logged_members) {
            rawstd_warning("  ...\n");
            break;
        }
        RawstdUUID id{};
        memcpy(id.bytes, member.first.data(), sizeof(id.bytes));
        RawstdUUIDString name;
        rawstd_uuid_to_string(&id, &name);
        rawstd_warning("  %s/%llx\n", name, (unsigned long long)member.second);
    }
}

bool cancelled(const std::exception& e) {
    auto* error = dynamic_cast<const std::system_error*>(&e);
    return error != nullptr && error->code().value() == ECANCELED;
}

} // namespace

Reconciler::Reconciler(ObjectStore& store) :
    _store(store),
    _wake(rawstd::Pipe::Mode::NonBlocking),
    _queue(rawio::Queue::create(64)) {
}

Reconciler::~Reconciler() = default;

void Reconciler::request(const TopologyOST& ost) {
    {
        std::lock_guard<std::mutex> lock(_mutex);
        for (const TopologyOST& pending : _requests) {
            if (rawstd_uuid_cmp(&pending.id, &ost.id) == 0) {
                return;
            }
        }
        _requests.push_back(ost);
    }
    char byte = 0;
    ssize_t ignored = write(_wake.write_fd(), &byte, 1);
    (void)ignored;
}

void Reconciler::stop() noexcept {
    _stop_requested = true;
    char byte = 0;
    ssize_t ignored = write(_wake.write_fd(), &byte, 1);
    (void)ignored;
}

/*
 * The map's members are read before the listing and after it: one that is in
 * neither is one the OST holds alone, one that is in both one it lacks. A
 * member created or removed meanwhile is in one of them only, and is not a
 * difference.
 */
rawstd::Task<void> Reconciler::_reconcile(TopologyOST ost) {
    RawstdUUIDString name;
    rawstd_uuid_to_string(&ost.id, &name);
    try {
        std::set<MemberKey> before = keys_of(_store.members_on(ost.id));
        std::set<MemberKey> listed;
        std::unique_ptr<Slot> slot =
            co_await Slot::create(*_queue, rawstd::URI(ost.location));
        std::exception_ptr error;
        try {
            RawstdUUID token{};
            do {
                std::vector<ChunkGroup> groups;
                co_await slot->list_chunks(
                    RawstdUUID{}, rawstor_opts_list_limit(), groups, token
                );
                for (const ChunkGroup& group : groups) {
                    for (uint64_t offset : group.offsets) {
                        listed.insert(key_of(group.id, offset));
                    }
                }
            } while (!rawstd_uuid_is_nil(&token));
        } catch (...) {
            error = std::current_exception();
        }
        co_await slot->close();
        if (error) {
            std::rethrow_exception(error);
        }
        std::set<MemberKey> after = keys_of(_store.members_on(ost.id));

        std::set<MemberKey> orphans;
        for (const MemberKey& member : listed) {
            if (!before.contains(member) && !after.contains(member)) {
                orphans.insert(member);
            }
        }
        std::set<MemberKey> missing;
        for (const MemberKey& member : before) {
            if (after.contains(member) && !listed.contains(member)) {
                missing.insert(member);
            }
        }
        if (orphans.empty() && missing.empty()) {
            rawstd_info("OST %s agrees with the map\n", name);
        }
        log_members(name, "holds, not in the map,", orphans);
        log_members(name, "lacks, placed on it by the map,", missing);
    } catch (const std::exception& e) {
        if (!cancelled(e)) {
            rawstd_warning(
                "Listing OST %s at %s failed: %s\n", name, ost.location.c_str(),
                e.what()
            );
        }
    }
}

rawstd::Task<void> Reconciler::_wake_reader() {
    char wake_ups[64];
    while (true) {
        size_t n = 0;
        try {
            n = co_await _queue->read(
                _wake.read_fd(), wake_ups, sizeof(wake_ups)
            );
        } catch (const std::system_error& e) {
            if (e.code().value() == ECANCELED) {
                co_return;
            }
            throw;
        }
        if (n == 0 || _stop_requested) {
            if (_work && !_work->done()) {
                _work->cancel_sticky();
            }
            _pending.release();
            co_return;
        }
        _pending.release();
    }
}

rawstd::Task<void> Reconciler::_control() {
    while (true) {
        co_await _pending.acquire();
        if (_stop_requested) {
            break;
        }
        std::vector<TopologyOST> requests;
        {
            std::lock_guard<std::mutex> lock(_mutex);
            requests.swap(_requests);
        }
        for (TopologyOST& ost : requests) {
            if (_stop_requested) {
                break;
            }
            _work.emplace(_reconcile(std::move(ost)));
            rawstd::Task<void>& work = *_work;
            co_await work;
        }
        _work.reset();
    }
}

void Reconciler::loop() {
    rawstd::Task<void> reader = _wake_reader();
    rawstd::Task<void> control = _control();
    auto pump = [this](const rawstd::Task<void>& task) {
        while (!task.done()) {
            try {
                _queue->wait();
            } catch (const std::system_error& e) {
                if (e.code().value() != EINTR) {
                    throw;
                }
            }
        }
    };
    pump(control);
    reader.cancel();
    pump(reader);
    reader.get();
    control.get();
}

} // namespace mdsserver
} // namespace rawstor
