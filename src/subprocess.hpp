#ifndef RAWSTOR_SUBPROCESS_HPP
#define RAWSTOR_SUBPROCESS_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <string>
#include <vector>

namespace rawstor {

// Runs argv[0] to completion on a detached thread, so the calling
// coroutine's event loop keeps servicing other work while it does, and
// captures everything it wrote to stdout. The thread hands its result back
// across a pipe whose read end is driven through `queue`, so the
// coroutine resumes on the same event loop it suspended from. Used for
// read-only inspection commands (lvs/vgs, zfs list, ...) whose output this
// process needs to parse. Throws std::system_error on any failure.
rawstd::Task<std::string>
run_command_capture(rawio::Queue& queue, std::vector<std::string> argv);

// Runs `argv` to completion the same way as run_command_capture() above,
// but without capturing output -- lvcreate/zfs-create/zfs-destroy can take
// anywhere from milliseconds to seconds depending on the backing storage.
// Throws std::system_error on any failure.
rawstd::Task<void>
run_command(rawio::Queue& queue, std::vector<std::string> argv);

} // namespace rawstor

#endif // RAWSTOR_SUBPROCESS_HPP
