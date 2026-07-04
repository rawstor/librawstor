#ifndef RAWSTOR_SUBPROCESS_HPP
#define RAWSTOR_SUBPROCESS_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace rawstor {

// Runs argv[0] to completion, blocking the calling thread. Returns 0 on a
// zero exit status, or a positive errno otherwise (EIO if the child ran but
// exited non-zero or was killed by a signal).
int run_command(const std::vector<std::string>& argv);

// Runs argv[0] the same way as run_command(), but captures everything it
// wrote to stdout. Used for read-only inspection commands (lvs/vgs, zfs
// list, ...) whose output this process needs to parse.
std::pair<int, std::string>
run_command_capture(const std::vector<std::string>& argv);

// Returns the size in bytes of the block device at `path`, via
// ioctl(BLKGETSIZE64). Throws std::system_error on any failure (device
// missing, not a block device, ...).
uint64_t block_device_size(const std::string& path);

// Polls for `path` to show up as a block device, for up to `timeout_ms`.
// Returns 0 once it does, ETIMEDOUT otherwise. LVM/ZFS both create their
// device node asynchronously with respect to lvcreate/zfs-create(8)
// returning, so create() below must wait for it before handing the object
// back to the caller.
int wait_for_blockdev(const std::string& path, int timeout_ms = 5000);

// Runs `argv` (via run_command() above) on a detached thread, so the
// calling coroutine's event loop keeps servicing other work while it does
// -- lvcreate/zfs-create/zfs-destroy can take anywhere from milliseconds to
// seconds depending on the backing storage. If `wait_path` is non-empty and
// `argv` succeeds, the thread also wait_for_blockdev()s it before reporting
// completion. The thread hands its result back across a pipe whose read end
// is driven through `queue`, so the coroutine resumes on the same event
// loop it suspended from. Throws std::system_error on any failure.
rawstd::Task<void> run_command_async(
    rawio::Queue& queue, std::vector<std::string> argv, std::string wait_path
);

} // namespace rawstor

#endif // RAWSTOR_SUBPROCESS_HPP
