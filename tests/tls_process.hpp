#ifndef RAWSTOR_TESTS_TLS_PROCESS_HPP
#define RAWSTOR_TESTS_TLS_PROCESS_HPP

#include <pki.hpp>

#include <rawstd/gpp.hpp>

#include <rawstor/rawstor.h>

#include <cstdlib>
#include <string>

namespace rawstor {
namespace tests {

// Makes this process speak TLS with the identity `uri` names, the way the
// environment of a service would, for as long as it lives; the certificate
// is issued by `pki`, which a peer must trust to talk to it.
class TlsProcess {
private:
    static void restart() {
        rawstor_terminate();
        int res = rawstor_initialize(nullptr);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }

public:
    static const std::string trust_domain;

    rawtls::testing::Pki pki;
    rawtls::testing::Identity identity;

    explicit TlsProcess(const std::string& uri) {
        rawtls::testing::IssueOptions options;
        options.uris = {uri};
        identity = pki.issue("process", options);
        setenv("RAWSTOR_TLS_TRUST_DOMAIN", trust_domain.c_str(), 1);
        setenv("RAWSTOR_TLS_CERT", identity.cert_file.c_str(), 1);
        setenv("RAWSTOR_TLS_KEY", identity.key_file.c_str(), 1);
        setenv("RAWSTOR_TLS_CA", pki.ca_file().c_str(), 1);
        restart();
    }

    TlsProcess(const TlsProcess&) = delete;
    TlsProcess& operator=(const TlsProcess&) = delete;

    ~TlsProcess() {
        unsetenv("RAWSTOR_TLS_TRUST_DOMAIN");
        unsetenv("RAWSTOR_TLS_CERT");
        unsetenv("RAWSTOR_TLS_KEY");
        unsetenv("RAWSTOR_TLS_CA");
        restart();
    }
};

inline const std::string TlsProcess::trust_domain = "cluster.example";

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_TLS_PROCESS_HPP
