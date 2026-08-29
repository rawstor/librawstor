#ifndef RAWSTOR_SESSION_ERROR_HPP
#define RAWSTOR_SESSION_ERROR_HPP

#include <system_error>

namespace rawstor {

// Thrown by a Session (currently only ost::Session -- see ost_session.cpp)
// when it couldn't even talk to its backend: connect() failed, a send/recv
// broke mid-flight, the session was torn down out from under a still-
// pending op (Session::_fail_in_flight()), or the response that did come
// back isn't a well-formed OST frame. The session itself is suspect, not
// just this one request -- Connection::_with_retry() reacts by
// reconnecting (invalidate_session()) and retrying, effectively without a
// bound (see RawstorOpts::io_wire_retry_attempts), the same way a QEMU
// vhost-user chardev's own `reconnect=N` keeps trying forever: the network
// can come back at any time, and the caller should stall rather than see a
// stream of spurious errors for a blip.
class TransportError : public std::system_error {
public:
    using std::system_error::system_error;
};

// Thrown when a Session's backend answered with a complete, well-formed
// response that just happens to carry a failure -- the connection itself
// is fine, this specific request was rejected. Connection::_with_retry()
// reacts by retrying against the *same* session (no reconnect -- nothing
// about the transport is broken, so reconnecting would only cost a round
// trip for nothing), bounded by RawstorOpts::io_attempts, unless the
// rejection is one _with_retry() already knows can never succeed on retry
// (e.g. ENOENT), in which case it doesn't retry at all.
class BackendError : public std::system_error {
public:
    using std::system_error::system_error;
};

} // namespace rawstor

#endif // RAWSTOR_SESSION_ERROR_HPP
