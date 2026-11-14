#include <rawtls/context.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cerrno>

namespace rawtls {

namespace {

void log_errors(const char* what, const std::string& file) {
    unsigned long code;
    char text[256];
    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, text, sizeof(text));
        rawstd_error("%s %s: %s\n", what, file.c_str(), text);
    }
}

std::shared_ptr<ssl_ctx_st> build(const Config& config) {
    ERR_clear_error();
    SSL_CTX* raw = SSL_CTX_new(TLS_method());
    if (raw == nullptr) {
        log_errors("TLS context", "");
        RAWSTD_THROW_SYSTEM_ERROR(ENOMEM);
    }
    std::shared_ptr<ssl_ctx_st> ctx(raw, SSL_CTX_free);

    if (SSL_CTX_set_min_proto_version(raw, TLS1_3_VERSION) != 1) {
        log_errors("TLS version", "");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    SSL_CTX_set_session_cache_mode(raw, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(raw, 0);
    SSL_CTX_set_options(raw, SSL_OP_NO_TICKET);
    SSL_CTX_set_mode(raw, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_verify(
        raw, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr
    );

    if (SSL_CTX_use_certificate_chain_file(raw, config.cert_file.c_str()) !=
        1) {
        log_errors("Cannot load the certificate", config.cert_file);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (SSL_CTX_use_PrivateKey_file(
            raw, config.key_file.c_str(), SSL_FILETYPE_PEM
        ) != 1) {
        log_errors("Cannot load the private key", config.key_file);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (SSL_CTX_check_private_key(raw) != 1) {
        log_errors("The private key does not match", config.cert_file);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (SSL_CTX_load_verify_locations(raw, config.ca_file.c_str(), nullptr) !=
        1) {
        log_errors("Cannot load the CA bundle", config.ca_file);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (!config.crl_file.empty()) {
        X509_STORE* store = SSL_CTX_get_cert_store(raw);
        X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (lookup == nullptr ||
            X509_load_crl_file(
                lookup, config.crl_file.c_str(), X509_FILETYPE_PEM
            ) <= 0) {
            log_errors("Cannot load the CRL", config.crl_file);
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    }
    return ctx;
}

} // namespace

Context::Context(const Config& config) :
    _config(config),
    _ctx(build(config)),
    _reload_requested(false) {
}

std::shared_ptr<ssl_ctx_st> Context::_snapshot() {
    // The rebuild is done under the lock: a session created while it runs
    // waits for it instead of starting from the credentials being replaced.
    std::lock_guard<std::mutex> lock(_mutex);
    if (_reload_requested.exchange(false)) {
        try {
            _ctx = build(_config);
            rawstd_info("TLS settings reloaded\n");
        } catch (const std::system_error& e) {
            rawstd_error(
                "TLS settings not reloaded, the old ones stay: %s\n", e.what()
            );
        }
    }
    return _ctx;
}

void Context::request_reload() noexcept {
    _reload_requested.store(true);
}

void Context::reload() {
    std::shared_ptr<ssl_ctx_st> ctx = build(_config);
    std::lock_guard<std::mutex> lock(_mutex);
    _ctx = std::move(ctx);
}

} // namespace rawtls
