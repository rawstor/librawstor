#ifndef RAWSTOR_TLS_HPP
#define RAWSTOR_TLS_HPP

#include <rawstor/protocol.h>
#include <rawtls/context.hpp>
#include <rawtls/transport.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <string>

namespace rawstor {
namespace tls {

/*
 * Reads the TLS settings of the process (src/opts.h) and loads the certificate,
 * key and CAs they name. Does nothing, and leaves TLS off, when the settings
 * are absent. Throws std::system_error if they are there but cannot be loaded.
 */
void initialize();

// The authenticated client tenant, or the built-in default for a provider.
RawstdUUID default_owner();

void terminate() noexcept;

// The process's TLS context, null when TLS is off.
rawtls::Context* context() noexcept;

/*
 * Reads the certificate, key and CAs again before the next connection is made:
 * connections already established keep what they started with. Safe in a
 * signal handler. Without TLS settings it does nothing; if a file cannot be
 * read the error is logged and the old settings stay.
 */
void request_reload() noexcept;

/*
 * Records that the server at `host` (`host:port`, as URI::host() spells it) is
 * the OST `ost_id`, as the MDS said when it resolved an object. A TLS
 * connection to that address then requires that OST's identity, so one OST
 * cannot answer for another. Has no effect when TLS is off.
 */
void expect_ost(const std::string& host, const RawstdUUID& ost_id);

struct Capability {
    RawstorCapability token;
    std::string resolver;
};
void remember_capability(
    const std::string& host, const RawstorCapability& token,
    const std::string& resolver
);
Capability capability(
    const std::string& host, const RawstdUUID& object, uint64_t offset,
    const RawstdUUID& version
);

/*
 * The Transport of a connected socket to the server at `host` of `scheme`
 * (`ost` or `mds`): plain when TLS is off, otherwise the TLS client side of it,
 * after the handshake. The server must be the OST recorded for `host` by
 * expect_ost(); an address with none recorded accepts any server of the
 * scheme's role. An `ost` address that has completed a handshake as an
 * `mds` is the witness the MDS hosts on its own port: the server must be that
 * MDS (the one RAWSTOR_TLS_MDS_ID names, if any), not an OST.
 */
rawstd::Task<std::unique_ptr<rawtls::Transport>> connect(
    rawio::Queue& queue, int fd, const std::string& scheme,
    const std::string& host
);

/*
 * The Transport of an accepted socket: plain when TLS is off, otherwise the TLS
 * server side of it, after the handshake. A client that does not complete it
 * in time, or that is refused, fails it.
 */
rawstd::Task<std::unique_ptr<rawtls::Transport>>
accept(rawio::Queue& queue, int fd);

} // namespace tls
} // namespace rawstor

#endif // RAWSTOR_TLS_HPP
