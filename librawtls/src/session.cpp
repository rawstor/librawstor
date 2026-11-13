#include <rawtls/session.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>

namespace rawtls {

namespace {

int chunk(size_t size) noexcept {
    return static_cast<int>(std::min<size_t>(size, INT_MAX));
}

void log_errors(const char* what) {
    unsigned long code;
    char text[256];
    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, text, sizeof(text));
        rawstd_error("%s: %s\n", what, text);
    }
}

[[noreturn]] void refuse(const char* reason) {
    rawstd_warning("Peer refused: %s\n", reason);
    RAWSTD_THROW_SYSTEM_ERROR(EACCES);
}

} // namespace

Session::Session(
    Context& context, Mode mode, const std::string& expected_peer
) :
    _ctx(context._snapshot()),
    _ssl(nullptr),
    _rbio(nullptr),
    _wbio(nullptr),
    _mode(mode),
    _trust_domain(context.trust_domain()),
    _expected_peer(expected_peer),
    _handshake_done(false),
    _verify_failed(false),
    _closed(false) {
    if (mode == Mode::client) {
        // A client that does not know whom it is talking to would accept any
        // certificate of the CA.
        if (!SpiffeId::parse(expected_peer).is_server()) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    _ssl = SSL_new(_ctx.get());
    if (_ssl == nullptr) {
        log_errors("TLS session");
        RAWSTD_THROW_SYSTEM_ERROR(ENOMEM);
    }
    _rbio = BIO_new(BIO_s_mem());
    _wbio = BIO_new(BIO_s_mem());
    if (_rbio == nullptr || _wbio == nullptr) {
        BIO_free(_rbio);
        BIO_free(_wbio);
        SSL_free(_ssl);
        RAWSTD_THROW_SYSTEM_ERROR(ENOMEM);
    }
    // The SSL owns both BIOs from here on.
    SSL_set_bio(_ssl, _rbio, _wbio);
    SSL_set_app_data(_ssl, this);
    SSL_set_verify(
        _ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, _verify
    );
    if (mode == Mode::client) {
        SSL_set_connect_state(_ssl);
    } else {
        SSL_set_accept_state(_ssl);
    }
}

Session::~Session() {
    SSL_free(_ssl);
}

int Session::_verify(int ok, x509_store_ctx_st* store_ctx) {
    SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(
        store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()
    ));
    Session* self = static_cast<Session*>(SSL_get_app_data(ssl));
    if (!ok) {
        self->_verify_failed = true;
        return 0;
    }
    // The chain is walked from the root down to the peer's own certificate,
    // which is the one that carries the identity.
    if (X509_STORE_CTX_get_error_depth(store_ctx) != 0) {
        return 1;
    }
    try {
        self->_peer =
            self->_check_peer(X509_STORE_CTX_get_current_cert(store_ctx));
    } catch (const std::system_error&) {
        self->_verify_failed = true;
        X509_STORE_CTX_set_error(
            store_ctx, X509_V_ERR_APPLICATION_VERIFICATION
        );
        return 0;
    }
    return 1;
}

SpiffeId Session::_check_peer(x509_st* cert) const {
    if (X509_check_ca(cert) != 0) {
        refuse("the certificate is a CA");
    }

    // Absent extended key usage is not "any": the certificate must say it may
    // be used for the end of the connection it is on.
    uint32_t usage = X509_get_extended_key_usage(cert);
    uint32_t needed = _mode == Mode::client ? XKU_SSL_SERVER : XKU_SSL_CLIENT;
    if (usage == UINT32_MAX || !(usage & needed)) {
        refuse("the certificate lacks the extended key usage");
    }

    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)
    );
    if (names == nullptr) {
        refuse("the certificate has no subject alternative name");
    }
    std::string uri;
    int uris = 0;
    bool embedded_nul = false;
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
        if (name->type != GEN_URI) {
            continue;
        }
        ++uris;
        const ASN1_IA5STRING* value = name->d.uniformResourceIdentifier;
        const char* data =
            reinterpret_cast<const char*>(ASN1_STRING_get0_data(value));
        size_t size = static_cast<size_t>(ASN1_STRING_length(value));
        if (memchr(data, 0, size) != nullptr) {
            embedded_nul = true;
        }
        uri.assign(data, size);
    }
    GENERAL_NAMES_free(names);
    if (uris != 1 || embedded_nul) {
        refuse("the certificate must have exactly one URI SAN");
    }

    SpiffeId id;
    try {
        id = SpiffeId::parse(uri);
    } catch (const std::system_error&) {
        refuse("the URI SAN is not a rawstor SPIFFE ID");
    }
    if (id.trust_domain != _trust_domain) {
        refuse("the SPIFFE ID is in another trust domain");
    }
    if (_mode == Mode::client) {
        if (!id.is_server()) {
            refuse("the server's SPIFFE ID is not that of an OST or an MDS");
        }
        if (id.uri != _expected_peer) {
            refuse("the server's SPIFFE ID is not the one expected");
        }
    }
    return id;
}

void Session::_fail(int result) {
    int error = SSL_get_error(_ssl, result);
    unsigned long first = ERR_peek_error();
    log_errors("TLS");
    if (_verify_failed ||
        (error == SSL_ERROR_SSL &&
         ERR_GET_REASON(first) == SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE)) {
        RAWSTD_THROW_SYSTEM_ERROR(EACCES);
    }
    RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
}

void Session::feed(const void* data, size_t size) {
    const char* p = static_cast<const char*>(data);
    while (size > 0) {
        int n = BIO_write(_rbio, p, chunk(size));
        if (n <= 0) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOMEM);
        }
        p += n;
        size -= static_cast<size_t>(n);
    }
}

size_t Session::output_size() const noexcept {
    return BIO_ctrl_pending(_wbio);
}

size_t Session::take_output(void* buf, size_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    int n = BIO_read(_wbio, buf, chunk(size));
    return n > 0 ? static_cast<size_t>(n) : 0;
}

bool Session::handshake() {
    if (_handshake_done) {
        return true;
    }
    ERR_clear_error();
    int result = SSL_do_handshake(_ssl);
    if (result == 1) {
        // The verify callback ran for every full handshake; a handshake that
        // finished without it has no identity to go by.
        if (!_peer.has_value()) {
            refuse("no identity was established");
        }
        _handshake_done = true;
        return true;
    }
    int error = SSL_get_error(_ssl, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        return false;
    }
    _fail(result);
}

const SpiffeId& Session::peer() const {
    if (!_peer.has_value() || !_handshake_done) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return *_peer;
}

void Session::encrypt(const void* data, size_t size) {
    if (!_handshake_done) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    const char* p = static_cast<const char*>(data);
    while (size > 0) {
        ERR_clear_error();
        int n = SSL_write(_ssl, p, chunk(size));
        if (n <= 0) {
            _fail(n);
        }
        p += n;
        size -= static_cast<size_t>(n);
    }
}

size_t Session::decrypt(void* buf, size_t size) {
    if (!_handshake_done) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (size == 0) {
        return 0;
    }
    ERR_clear_error();
    int n = SSL_read(_ssl, buf, chunk(size));
    if (n > 0) {
        return static_cast<size_t>(n);
    }
    int error = SSL_get_error(_ssl, n);
    if (error == SSL_ERROR_WANT_READ) {
        return 0;
    }
    if (error == SSL_ERROR_ZERO_RETURN) {
        _closed = true;
        return 0;
    }
    _fail(n);
}

void Session::shutdown() {
    ERR_clear_error();
    SSL_shutdown(_ssl);
    ERR_clear_error();
}

} // namespace rawtls
