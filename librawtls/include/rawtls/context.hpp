#ifndef RAWTLS_CONTEXT_HPP
#define RAWTLS_CONTEXT_HPP

#include <memory>
#include <mutex>
#include <string>

struct ssl_ctx_st;

namespace rawtls {

class Session;

struct Config {
    // The trust domain of this cluster: a peer whose SPIFFE ID is in another
    // trust domain is rejected, whoever signed its certificate.
    std::string trust_domain;
    // This process's certificate (with the chain that leads to the CA, if
    // any) and its private key, both PEM.
    std::string cert_file;
    std::string key_file;
    // The CAs a peer's certificate must chain to, PEM; several may be listed.
    std::string ca_file;
    // An optional CRL, PEM, checked for the peer's certificate.
    std::string crl_file;
};

/*
 * What a process needs to speak TLS 1.3 with mutual authentication, built from
 * the files of a Config. One Context serves every connection of the process,
 * client and server side; a Session takes the certificate, key and CAs the
 * Context holds when it is created.
 *
 * Session tickets are off: every connection makes a full handshake, so a peer's
 * certificate is checked against the CAs and the CRL of the moment.
 */
class Context final {
    friend class Session;

private:
    Config _config;
    std::mutex _mutex;
    std::shared_ptr<ssl_ctx_st> _ctx;

    std::shared_ptr<ssl_ctx_st> _snapshot();

public:
    // Throws std::system_error if a file cannot be read or does not hold what
    // it should (EINVAL), or the key does not belong to the certificate
    // (EINVAL).
    explicit Context(const Config& config);
    Context(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(const Context&) = delete;
    Context& operator=(Context&&) = delete;

    const std::string& trust_domain() const noexcept {
        return _config.trust_domain;
    }

    /*
     * Reads the files again. New sessions use the result; established ones
     * keep what they started with. If a file is unreadable or broken this
     * throws and the Context is unchanged, so a half-written renewal does not
     * take the process down.
     */
    void reload();
};

} // namespace rawtls

#endif // RAWTLS_CONTEXT_HPP
