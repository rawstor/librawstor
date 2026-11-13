#ifndef RAWSTOR_TLS_HPP
#define RAWSTOR_TLS_HPP

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

void terminate() noexcept;

// The process's TLS context, null when TLS is off.
rawtls::Context* context() noexcept;

/*
 * Records that the server at `host` (`host:port`, as URI::host() spells it) is
 * the OST `ost_id`, as the MDS said when it resolved an object. A TLS
 * connection to that address then requires that OST's identity, so one OST
 * cannot answer for another. Has no effect when TLS is off.
 */
void expect_ost(const std::string& host, const RawstdUUID& ost_id);

/*
 * The Transport of a connected socket to the server at `host` of `scheme`
 * (`ost` or `mds`): plain when TLS is off, otherwise the TLS client side of it,
 * after the handshake. The server must be the OST recorded for `host` by
 * expect_ost(); an address with none recorded accepts any server of the
 * scheme's role.
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
