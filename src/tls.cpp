#include "tls.hpp"

#include "opts.h"
#include <rawstor/location.h>
#include <rawtls/ca.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <atomic>
#include <cerrno>
#include <map>
#include <mutex>
#include <optional>
#include <set>

namespace {

std::mutex mutex;
std::unique_ptr<rawtls::Context> process_context;
RawstdUUID client_tenant{};
// The identity required of every MDS, empty to accept any MDS of the trust
// domain.
std::string mds_identity;
// The identity of the OST at each address the MDS has resolved.
std::map<std::string, std::string> ost_identities;
// The addresses that have completed a handshake as an MDS. An MDS hosts a
// witness on its own port, so an ost:// address among them is that MDS
// answering as the witness, and it presents its own identity.
std::set<std::string> mds_hosts;
// What request_reload() reaches from a signal handler, without the lock.
std::atomic<rawtls::Context*> signal_context{nullptr};

} // namespace

namespace rawstor {
namespace tls {

void initialize() {
    if (rawstor_opts_insecure()) {
        rawstd_warning(
            "INSECURE: this process runs without TLS, its connections are "
            "plaintext and no peer is authenticated\n"
        );
        return;
    }
    const char* trust_domain = rawstor_opts_tls_trust_domain();
    if (trust_domain == nullptr) {
        rawstd_error(
            "TLS is not configured: set RAWSTOR_TLS_TRUST_DOMAIN, "
            "RAWSTOR_TLS_CERT, RAWSTOR_TLS_KEY and RAWSTOR_TLS_CA, or run "
            "without TLS with --insecure\n"
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    rawtls::Config config;
    config.trust_domain = trust_domain;
    config.cert_file = rawstor_opts_tls_cert();
    config.key_file = rawstor_opts_tls_key();
    config.ca_file = rawstor_opts_tls_ca();
    if (rawstor_opts_tls_crl() != nullptr) {
        config.crl_file = rawstor_opts_tls_crl();
    }
    std::unique_ptr<rawtls::Context> context =
        std::make_unique<rawtls::Context>(config);
    std::string mds;
    if (rawstor_opts_tls_mds_id() != nullptr) {
        mds = "spiffe://" + config.trust_domain + "/mds/" +
              rawstor_opts_tls_mds_id();
        // Only the name of an MDS in this trust domain makes an identity.
        bool valid = false;
        try {
            valid = rawtls::SpiffeId(mds).role() == rawtls::Role::mds;
        } catch (const std::system_error&) {
        }
        if (!valid) {
            rawstd_error(
                "Invalid RAWSTOR_TLS_MDS_ID: %s\n", rawstor_opts_tls_mds_id()
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
    std::lock_guard<std::mutex> lock(mutex);
    rawtls::SpiffeId own(rawtls::inspect(config.cert_file).identity);
    client_tenant = {};
    if (own.role() == rawtls::Role::client) {
        rawstd_uuid_from_string(&client_tenant, own.tenant().c_str());
    }
    process_context = std::move(context);
    mds_identity = std::move(mds);
    signal_context.store(process_context.get());
}

RawstdUUID default_owner() {
    std::lock_guard<std::mutex> lock(mutex);
    if (!rawstd_uuid_is_nil(&client_tenant)) {
        return client_tenant;
    }
    RawstdUUID result{};
    rawstd_uuid_from_string(&result, RAWSTOR_DEFAULT_TENANT);
    return result;
}

void terminate() noexcept {
    std::lock_guard<std::mutex> lock(mutex);
    signal_context.store(nullptr);
    process_context.reset();
    client_tenant = {};
    mds_identity.clear();
    ost_identities.clear();
    mds_hosts.clear();
}

void request_reload() noexcept {
    rawtls::Context* c = signal_context.load();
    if (c != nullptr) {
        c->request_reload();
    }
}

rawtls::Context* context() noexcept {
    std::lock_guard<std::mutex> lock(mutex);
    return process_context.get();
}

void expect_ost(const std::string& host, const RawstdUUID& ost_id) {
    std::lock_guard<std::mutex> lock(mutex);
    if (!process_context) {
        return;
    }
    RawstdUUIDString id;
    rawstd_uuid_to_string(&ost_id, &id);
    ost_identities[host] =
        "spiffe://" + process_context->trust_domain() + "/ost/" + id;
}

rawstd::Task<std::unique_ptr<rawtls::Transport>> connect(
    rawio::Queue& queue, int fd, const std::string& scheme,
    const std::string& host
) {
    rawtls::Context* c = context();
    if (c == nullptr) {
        co_return rawtls::Transport::plain(queue, fd);
    }
    std::optional<rawtls::Role> role;
    std::string expected_peer;
    if (scheme == "ost") {
        std::lock_guard<std::mutex> lock(mutex);
        if (mds_hosts.count(host) != 0) {
            // The MDS's own witness: the server is the MDS this process was
            // configured with, not an OST the MDS named.
            role = rawtls::Role::mds;
            expected_peer = mds_identity;
        } else {
            role = rawtls::Role::ost;
            std::map<std::string, std::string>::const_iterator it =
                ost_identities.find(host);
            if (it != ost_identities.end()) {
                expected_peer = it->second;
            }
        }
    } else if (scheme == "mds") {
        role = rawtls::Role::mds;
        std::lock_guard<std::mutex> lock(mutex);
        expected_peer = mds_identity;
    } else {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::unique_ptr<rawtls::Transport> transport =
        co_await rawtls::Transport::tls(
            queue, fd, *c, rawtls::Mode::client, expected_peer, role
        );
    if (scheme == "mds") {
        // Only an address that has answered as an MDS is one: a refused
        // handshake, or a server of another role, does not make it so.
        std::lock_guard<std::mutex> lock(mutex);
        mds_hosts.insert(host);
    }
    co_return transport;
}

rawstd::Task<std::unique_ptr<rawtls::Transport>>
accept(rawio::Queue& queue, int fd) {
    rawtls::Context* c = context();
    if (c == nullptr) {
        co_return rawtls::Transport::plain(queue, fd);
    }
    co_return co_await rawtls::Transport::tls(
        queue, fd, *c, rawtls::Mode::server
    );
}

} // namespace tls
} // namespace rawstor
