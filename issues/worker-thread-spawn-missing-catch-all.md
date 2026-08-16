# worker.cpp: thread-spawn only catches std::system_error, not everything

## Where

`src/worker.cpp:59-83`, `run_in_worker()`:

```cpp
try {
    std::thread([work = std::move(work), wfd]() {
        int res;
        try {
            res = work();
        } catch (const std::system_error& e) {
            res = e.code().value();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            res = EIO;
        } catch (...) {                       // <-- inside the thread: full catch-all
            rawstd_error("Unexpected error\n");
            res = EIO;
        }
        ...
    }).detach();
} catch (const std::system_error& e) {        // <-- around the spawn itself: only system_error
    int res = e.code().value();
    ssize_t n = write(wfd, &res, sizeof(res));
    (void)n;
    close(wfd);
}
```

## Problem

The lambda that runs *inside* the spawned thread is fully defensive (`catch
(...)` at the end, matching the rest of the codebase's posture of never
letting an unexpected exception escape a callback). The `try` around the
`std::thread` *constructor* itself — which is what can throw if the OS fails
to create the thread (`EAGAIN` on thread/resource limits, most commonly
surfaced as `std::system_error`) — only catches `std::system_error`. If
`std::thread`'s constructor or anything reachable from it throws something
else (e.g. `std::bad_alloc` from an internal allocation failure), it
propagates out of `run_in_worker()` uncaught, which — for a control-plane
call made from the middle of the event loop's dispatch — would likely
terminate the process rather than being reported to the caller as an error.

## Suggested fix

Add a `catch (...)` alongside the existing `catch (const std::system_error&)`
around the `std::thread(...).detach()` call, mirroring the in-thread handling
(treat as `EIO`, log via `rawstd_error`), so a thread-spawn failure of any
kind degrades to an ordinary error callback instead of a potential crash.

## Note

Pre-existing (not introduced by the `add/mirror-metadata` work), surfaced
during AI review of that branch. Not yet fixed.
