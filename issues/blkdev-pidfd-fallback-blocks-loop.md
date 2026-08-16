# blkdev backends: pidfd_open() failure falls back to a blocking waitpid()

## Where

`src/blkdev_session.cpp`, in `BlkdevSession::run_async()` (around line 266-278)
and `BlkdevSession::run_async_capture()` (around line 393-402): both spawn an
external command (`lvcreate`, `zfs create`, `zfs set`, `lvs`, ...) and, on
`pidfd_open()` failure, do this:

```cpp
st->pidfd = static_cast<int>(syscall(SYS_pidfd_open, st->pid, 0));
if (st->pidfd == -1) {
    /*
     * Not expected on kernels recent enough for io_uring; reap
     * synchronously as a last resort so the child does not linger
     * as a zombie.
     */
    int err = errno;
    int status;
    waitpid(st->pid, &status, 0);   // <-- blocking, no WNOHANG
    st->cb(err);
    return;
}
```

The same pattern (blocking `waitpid(..., 0)`) also appears as the fallback
when `queue.poll(pidfd, ...)` submission itself throws.

## Problem

`waitpid(pid, &status, 0)` (no `WNOHANG`) blocks the calling thread until the
child exits. Since `run_async`/`run_async_capture` are called directly from
the single-threaded event loop (not from a worker thread), this blocks *every*
other in-flight operation on the whole process for as long as the spawned
command runs — potentially seconds, for `lvcreate`/`zfs create` on a busy
pool. The comment ("not expected on kernels recent enough for io_uring")
correctly notes this should be rare in practice, but "rare" is not "never":
older kernels, restrictive seccomp/container profiles, or `pid` namespace
edge cases can all make `pidfd_open()` fail on a system where io_uring itself
still works fine, and there's no reason to have io_uring available yet be
missing pidfd_open specifically. When it happens, the whole event loop stalls
for the command's runtime instead of just this one operation being slow.

## Suggested fix

Move the fallback `waitpid()` off the event-loop thread — e.g. reuse
`run_in_worker()` (already in `src/worker.hpp`, used by `file::Session`'s
control-plane I/O) to perform the blocking reap on a detached thread instead
of inline. This keeps the "reap so the child doesn't linger as a zombie"
guarantee without blocking the loop.

## Note

Pre-existing (not introduced by the `add/mirror-metadata` work), surfaced
during AI review of that branch. Not yet fixed.
