# Tracked findings

Notes on known gaps and defects surfaced during the `add/mirror-metadata`
work (mirroring implementation + review) that are out of scope for that
branch but should be picked up as follow-up work. Not filed upstream yet.

| File | Summary |
|------|---------|
| [vhost-unclean-close-and-flush.md](vhost-unclean-close-and-flush.md) | `rawstor-vhost` uses the unclean `rawstor_object_close`, never `_async`; guest `FLUSH` is rejected as unsupported instead of proxied to `rawstor_object_flush`. |
| [blkdev-pidfd-fallback-blocks-loop.md](blkdev-pidfd-fallback-blocks-loop.md) | `BlkdevSession::run_async{,_capture}()` falls back to a blocking `waitpid()` on the event-loop thread if `pidfd_open()` fails. |
| [worker-thread-spawn-missing-catch-all.md](worker-thread-spawn-missing-catch-all.md) | `run_in_worker()`'s `std::thread` spawn only catches `std::system_error`, not a general `catch (...)`, unlike the code running inside the thread. |
| [file-spec-format-forward-compat.md](file-spec-format-forward-compat.md) | An old (pre-mirroring) librawstor build reading a new versioned `.spec` file would compute a garbage size instead of erroring out; only matters for a mixed-version deployment sharing a `file://` directory. |
| [cli-quorum-tooling-missing.md](cli-quorum-tooling-missing.md) | `rawstor-cli force-open`/`status`/`resolve` (the operator-facing side of the quorum model) were never implemented. |
