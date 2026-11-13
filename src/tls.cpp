#include "tls.hpp"

#include "opts.h"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <cerrno>
#include <map>
#include <mutex>
#include <optional>

namespace rawstor {
namespace tls {

namespace {

std::mutex mutex;
std::unique_ptr<rawtls::Context> process_context;
// The identity of the OST at each address the MDS has resolved.
std::map<std::string, std::string> ost_identities;

} // namespace

void initialize() {
    const char* trust_domain = rawstor_opts_tls_trust_domain();
    if (trust_domain == nullptr) {
        rawstd_warning(
            "TLS is not configured: connections are plaintext and no peer is "
            "authenticated\n"
        );
        return;
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
    std::lock_guard<std::mutex> lock(mutex);
    process_context = std::move(context);
}

void terminate() noexcept {
    std::lock_guard<std::mutex> lock(mutex);
    process_context.reset();
    ost_identities.clear();
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
        role = rawtls::Role::ost;
        std::lock_guard<std::mutex> lock(mutex);
        std::map<std::string, std::string>::const_iterator it =
            ost_identities.find(host);
        if (it != ost_identities.end()) {
            expected_peer = it->second;
        }
    } else if (scheme == "mds") {
        role = rawtls::Role::mds;
    } else {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    co_return co_await rawtls::Transport::tls(
        queue, fd, *c, rawtls::Session::Mode::client, expected_peer, role
    );
}

} // namespace tls
} // namespace rawstor
