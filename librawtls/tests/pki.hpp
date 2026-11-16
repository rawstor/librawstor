#ifndef RAWTLS_TESTS_PKI_HPP
#define RAWTLS_TESTS_PKI_HPP

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

namespace rawtls {
namespace testing {

struct Identity {
    std::string cert_file;
    std::string key_file;
    unsigned serial;
};

struct IssueOptions {
    // The URI SANs; none means no SAN extension at all.
    std::vector<std::string> uris;
    // The extended key usages; both false and `usage` true is "none listed".
    bool server_auth = true;
    bool client_auth = true;
    bool usage = true;
    bool ca = false;
    // Offsets of the validity period from now, in seconds.
    long not_before = -3600;
    long not_after = 3600;
};

/*
 * A throwaway CA and the certificates it issues, written as PEM files into a
 * temporary directory that goes away with the object.
 */
class Pki final {
private:
    std::filesystem::path _dir;
    EVP_PKEY* _key;
    X509* _cert;
    unsigned _serial;

    static void check(bool ok, const char* what) {
        if (!ok) {
            throw std::runtime_error(what);
        }
    }

    static EVP_PKEY* new_key() {
        EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
        check(key != nullptr, "key generation");
        return key;
    }

    static void
    add_extension(X509* cert, X509* issuer, int nid, const std::string& value) {
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
        X509_EXTENSION* ext =
            X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
        check(ext != nullptr, "extension");
        check(X509_add_ext(cert, ext, -1) == 1, "add extension");
        X509_EXTENSION_free(ext);
    }

    static void set_name(X509_NAME* name, const std::string& common_name) {
        check(
            X509_NAME_add_entry_by_txt(
                name, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(common_name.c_str()), -1,
                -1, 0
            ) == 1,
            "name"
        );
    }

    X509* build(
        const std::string& name, EVP_PKEY* key, X509* issuer,
        EVP_PKEY* issuer_key, const IssueOptions& options
    ) {
        X509* cert = X509_new();
        check(cert != nullptr, "certificate");
        check(X509_set_version(cert, 2) == 1, "version");
        ASN1_INTEGER_set(X509_get_serialNumber(cert), ++_serial);
        check(
            X509_gmtime_adj(X509_getm_notBefore(cert), options.not_before) !=
                nullptr,
            "not before"
        );
        check(
            X509_gmtime_adj(X509_getm_notAfter(cert), options.not_after) !=
                nullptr,
            "not after"
        );
        set_name(X509_get_subject_name(cert), name);
        X509* signer = issuer != nullptr ? issuer : cert;
        if (issuer != nullptr) {
            check(
                X509_set_issuer_name(cert, X509_get_subject_name(issuer)) == 1,
                "issuer"
            );
        } else {
            check(
                X509_set_issuer_name(cert, X509_get_subject_name(cert)) == 1,
                "issuer"
            );
        }
        check(X509_set_pubkey(cert, key) == 1, "public key");

        if (options.ca) {
            add_extension(
                cert, signer, NID_basic_constraints, "critical,CA:TRUE"
            );
            add_extension(
                cert, signer, NID_key_usage, "critical,keyCertSign,cRLSign"
            );
        } else {
            add_extension(
                cert, signer, NID_basic_constraints, "critical,CA:FALSE"
            );
            add_extension(
                cert, signer, NID_key_usage, "critical,digitalSignature"
            );
        }
        if (!options.ca && options.usage) {
            std::string usage;
            if (options.server_auth) {
                usage += "serverAuth";
            }
            if (options.client_auth) {
                usage += usage.empty() ? "clientAuth" : ",clientAuth";
            }
            if (!usage.empty()) {
                add_extension(cert, signer, NID_ext_key_usage, usage);
            }
        }
        if (!options.uris.empty()) {
            std::string san;
            for (const std::string& uri : options.uris) {
                san += (san.empty() ? "URI:" : ",URI:") + uri;
            }
            add_extension(cert, signer, NID_subject_alt_name, san);
        }
        check(
            X509_sign(
                cert, issuer_key != nullptr ? issuer_key : key, EVP_sha256()
            ) > 0,
            "sign"
        );
        return cert;
    }

    std::string write(const std::string& name, X509* cert, EVP_PKEY* key) {
        std::string cert_file = (_dir / (name + ".crt")).string();
        std::string key_file = (_dir / (name + ".key")).string();
        FILE* f = fopen(cert_file.c_str(), "w");
        check(f != nullptr, "open certificate");
        check(PEM_write_X509(f, cert) == 1, "write certificate");
        fclose(f);
        if (key != nullptr) {
            f = fopen(key_file.c_str(), "w");
            check(f != nullptr, "open key");
            check(
                PEM_write_PrivateKey(
                    f, key, nullptr, nullptr, 0, nullptr, nullptr
                ) == 1,
                "write key"
            );
            fclose(f);
        }
        return cert_file;
    }

public:
    Pki() : _key(nullptr), _cert(nullptr), _serial(0) {
        std::string pattern =
            (std::filesystem::temp_directory_path() / "rawtls-XXXXXX").string();
        check(mkdtemp(pattern.data()) != nullptr, "temporary directory");
        _dir = pattern;
        _key = new_key();
        IssueOptions options;
        options.ca = true;
        options.not_before = -86400;
        options.not_after = 86400 * 30;
        _cert = build("rawtls test CA", _key, nullptr, nullptr, options);
        write("ca", _cert, nullptr);
    }

    Pki(const Pki&) = delete;
    Pki& operator=(const Pki&) = delete;

    ~Pki() {
        X509_free(_cert);
        EVP_PKEY_free(_key);
        std::error_code ignored;
        std::filesystem::remove_all(_dir, ignored);
    }

    const std::filesystem::path& dir() const { return _dir; }

    std::string ca_file() const { return (_dir / "ca.crt").string(); }

    Identity issue(const std::string& name, const IssueOptions& options) {
        EVP_PKEY* key = new_key();
        X509* cert = build(name, key, _cert, _key, options);
        unsigned serial = _serial;
        std::string cert_file = write(name, cert, key);
        X509_free(cert);
        EVP_PKEY_free(key);
        return Identity{cert_file, (_dir / (name + ".key")).string(), serial};
    }

    // A CRL from this CA that lists the given serial numbers as revoked.
    std::string crl(const std::vector<unsigned>& revoked) {
        X509_CRL* crl = X509_CRL_new();
        check(crl != nullptr, "crl");
        check(X509_CRL_set_version(crl, 1) == 1, "crl version");
        check(
            X509_CRL_set_issuer_name(crl, X509_get_subject_name(_cert)) == 1,
            "crl issuer"
        );
        ASN1_TIME* last = ASN1_TIME_adj(nullptr, time(nullptr), 0, -3600);
        ASN1_TIME* next = ASN1_TIME_adj(nullptr, time(nullptr), 1, 0);
        X509_CRL_set1_lastUpdate(crl, last);
        X509_CRL_set1_nextUpdate(crl, next);
        ASN1_TIME_free(last);
        ASN1_TIME_free(next);
        for (unsigned serial : revoked) {
            X509_REVOKED* entry = X509_REVOKED_new();
            ASN1_INTEGER* number = ASN1_INTEGER_new();
            ASN1_INTEGER_set(number, serial);
            X509_REVOKED_set_serialNumber(entry, number);
            ASN1_INTEGER_free(number);
            ASN1_TIME* when = ASN1_TIME_adj(nullptr, time(nullptr), 0, -1800);
            X509_REVOKED_set_revocationDate(entry, when);
            ASN1_TIME_free(when);
            check(X509_CRL_add0_revoked(crl, entry) == 1, "revoke");
        }
        check(X509_CRL_sort(crl) == 1, "crl sort");
        check(X509_CRL_sign(crl, _key, EVP_sha256()) > 0, "crl sign");
        std::string file = (_dir / "ca.crl").string();
        FILE* f = fopen(file.c_str(), "w");
        check(f != nullptr, "open crl");
        check(PEM_write_X509_CRL(f, crl) == 1, "write crl");
        fclose(f);
        X509_CRL_free(crl);
        return file;
    }
};

} // namespace testing
} // namespace rawtls

#endif // RAWTLS_TESTS_PKI_HPP
