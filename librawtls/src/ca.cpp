#include <rawtls/ca.hpp>

#include <rawtls/spiffe.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

template <typename T, void (*Free)(T*)>
struct Deleter {
    void operator()(T* p) const noexcept { Free(p); }
};

using Key = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using Cert = std::unique_ptr<X509, Deleter<X509, X509_free>>;
using Names =
    std::unique_ptr<GENERAL_NAMES, Deleter<GENERAL_NAMES, GENERAL_NAMES_free>>;

// No logging here: a CA is used by programs that have not initialized
// librawstor, so what went wrong travels in the exception.
[[noreturn]] void raise(int errnum, const std::string& message) {
    throw std::system_error(errnum, std::generic_category(), message);
}

[[noreturn]] void fail(const std::string& what, int errnum) {
    std::string message = what;
    unsigned long code;
    char text[256];
    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, text, sizeof(text));
        message += ": ";
        message += text;
    }
    raise(errnum, message);
}

void check(bool ok, const char* what) {
    if (!ok) {
        fail(what, EIO);
    }
}

std::string join(const std::string& dir, const char* name) {
    return dir + "/" + name;
}

Key new_key() {
    Key key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
    check(key != nullptr, "Key generation");
    return key;
}

void add_extension(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    check(ext != nullptr, "Certificate extension");
    int ok = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    check(ok == 1, "Certificate extension");
}

struct Profile {
    bool ca;
    std::string common_name;
    std::string uri;
};

// Both a CA certificate and the certificate of a process: they differ in the
// extensions only.
Cert build(
    const Profile& profile, EVP_PKEY* key, X509* issuer, EVP_PKEY* issuer_key,
    std::chrono::seconds validity
) {
    if (validity.count() <= 0 || validity.count() > 100LL * 365 * 86400) {
        raise(EINVAL, "The validity is from a second to a hundred years");
    }
    Cert cert(X509_new());
    check(cert != nullptr, "Certificate");
    X509* raw = cert.get();
    check(X509_set_version(raw, 2) == 1, "Certificate version");

    // A random serial: no state to keep, and nothing for two issuing
    // machines to clash on. Positive and not zero.
    unsigned char bytes[8];
    check(RAND_bytes(bytes, sizeof(bytes)) == 1, "Serial number");
    bytes[0] &= 0x7f;
    bytes[7] |= 1;
    std::unique_ptr<BIGNUM, Deleter<BIGNUM, BN_free>> serial(
        BN_bin2bn(bytes, sizeof(bytes), nullptr)
    );
    check(
        serial != nullptr &&
            BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(raw)) !=
                nullptr,
        "Serial number"
    );

    // A clock a little behind the peers' must not make a new certificate
    // not yet valid.
    check(
        X509_gmtime_adj(X509_getm_notBefore(raw), -300) != nullptr,
        "Certificate not before"
    );
    check(
        X509_gmtime_adj(
            X509_getm_notAfter(raw), static_cast<long>(validity.count())
        ) != nullptr,
        "Certificate not after"
    );

    X509_NAME* name = X509_get_subject_name(raw);
    check(
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_UTF8,
            reinterpret_cast<const unsigned char*>(profile.common_name.c_str()),
            -1, -1, 0
        ) == 1,
        "Certificate name"
    );
    check(
        X509_set_issuer_name(
            raw, X509_get_subject_name(issuer != nullptr ? issuer : raw)
        ) == 1,
        "Certificate issuer"
    );
    check(X509_set_pubkey(raw, key) == 1, "Certificate public key");

    X509* signer = issuer != nullptr ? issuer : raw;
    if (profile.ca) {
        add_extension(raw, signer, NID_basic_constraints, "critical,CA:TRUE");
        add_extension(
            raw, signer, NID_key_usage, "critical,keyCertSign,cRLSign"
        );
    } else {
        add_extension(raw, signer, NID_basic_constraints, "critical,CA:FALSE");
        add_extension(raw, signer, NID_key_usage, "critical,digitalSignature");
        add_extension(raw, signer, NID_ext_key_usage, "serverAuth,clientAuth");
        add_extension(
            raw, signer, NID_subject_alt_name, ("URI:" + profile.uri).c_str()
        );
    }
    check(
        X509_sign(raw, issuer_key != nullptr ? issuer_key : key, EVP_sha256()) >
            0,
        "Certificate signature"
    );
    return cert;
}

// Writes `file` through a temporary one in the same directory, so a process
// that reads it never sees half of it. `mode` is the mode of the new file.
template <typename Write>
void write_file(const std::string& file, mode_t mode, Write write) {
    std::string tmp = file + ".tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        raise(errno, "Cannot write " + file);
    }
    // umask may have taken bits off: a key must not end up with more than
    // asked, and a leftover file from an earlier run may have had more.
    if (fchmod(fd, mode) != 0) {
        int errsv = errno;
        close(fd);
        unlink(tmp.c_str());
        raise(errsv, "Cannot write " + file);
    }
    FILE* f = fdopen(fd, "w");
    if (f == nullptr) {
        int errsv = errno;
        close(fd);
        unlink(tmp.c_str());
        raise(errsv, "Cannot write " + file);
    }
    bool ok = write(f) && fflush(f) == 0 && fsync(fileno(f)) == 0;
    int errsv = ok ? 0 : (errno != 0 ? errno : EIO);
    if (fclose(f) != 0 && ok) {
        ok = false;
        errsv = errno;
    }
    if (!ok || rename(tmp.c_str(), file.c_str()) != 0) {
        if (ok) {
            errsv = errno;
        }
        unlink(tmp.c_str());
        raise(errsv, "Cannot write " + file);
    }
}

void write_cert(const std::string& file, X509* cert) {
    write_file(file, 0644, [&](FILE* f) {
        return PEM_write_X509(f, cert) == 1;
    });
}

void write_key(const std::string& file, EVP_PKEY* key) {
    write_file(file, 0600, [&](FILE* f) {
        return PEM_write_PrivateKey(
                   f, key, nullptr, nullptr, 0, nullptr, nullptr
               ) == 1;
    });
}

Cert read_cert(const std::string& file) {
    FILE* f = fopen(file.c_str(), "r");
    if (f == nullptr) {
        raise(errno, "Cannot open " + file);
    }
    Cert cert(PEM_read_X509(f, nullptr, nullptr, nullptr));
    fclose(f);
    if (cert == nullptr) {
        fail("Cannot read the certificate " + file, EINVAL);
    }
    return cert;
}

Key read_key(const std::string& file) {
    FILE* f = fopen(file.c_str(), "r");
    if (f == nullptr) {
        raise(errno, "Cannot open " + file);
    }
    Key key(PEM_read_PrivateKey(f, nullptr, nullptr, nullptr));
    fclose(f);
    if (key == nullptr) {
        fail("Cannot read the private key " + file, EINVAL);
    }
    return key;
}

// The one URI SAN of a certificate this CA issued.
std::string identity_of(X509* cert, const std::string& file) {
    Names names(
        static_cast<GENERAL_NAMES*>(
            X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)
        )
    );
    std::string uri;
    int count = 0;
    for (int i = 0; names != nullptr && i < sk_GENERAL_NAME_num(names.get());
         ++i) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), i);
        if (name->type != GEN_URI) {
            continue;
        }
        ++count;
        const ASN1_IA5STRING* ia5 = name->d.uniformResourceIdentifier;
        uri.assign(
            reinterpret_cast<const char*>(ASN1_STRING_get0_data(ia5)),
            static_cast<size_t>(ASN1_STRING_length(ia5))
        );
    }
    if (count != 1) {
        raise(EINVAL, file + " has not exactly one URI SAN");
    }
    return uri;
}

void make_dir(const std::string& dir) {
    if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
        raise(errno, "Cannot create " + dir);
    }
}

} // namespace

namespace rawtls {

void Ca::init(
    const std::string& dir, const std::string& common_name,
    std::chrono::seconds validity
) {
    ERR_clear_error();
    if (common_name.empty()) {
        raise(EINVAL, "The CA needs a name");
    }
    make_dir(dir);
    if (access(join(dir, "ca.key").c_str(), F_OK) == 0 ||
        access(join(dir, "ca.crt").c_str(), F_OK) == 0) {
        raise(EEXIST, dir + " has a CA already");
    }
    Key key = new_key();
    Cert cert = build(
        Profile{true, common_name, ""}, key.get(), nullptr, nullptr, validity
    );
    // The key first: a CA certificate without its key is useless, a key
    // without a certificate is only a leftover.
    write_key(join(dir, "ca.key"), key.get());
    write_cert(join(dir, "ca.crt"), cert.get());
}

Ca::Ca(const std::string& dir) : _dir(dir) {
    ERR_clear_error();
    if (access(join(dir, "ca.crt").c_str(), R_OK) != 0 ||
        access(join(dir, "ca.key").c_str(), R_OK) != 0) {
        raise(errno, "No CA in " + dir);
    }
}

std::string Ca::ca_file() const {
    return join(_dir, "ca.crt");
}

void Ca::issue(
    const std::string& uri, std::chrono::seconds validity,
    const std::string& cert_file, const std::string& key_file
) const {
    ERR_clear_error();
    // The shape is the one a process is going to be checked against. The
    // identity is the SAN alone; the subject only has to be something to read
    // in a listing, and a common name is at most 64 bytes.
    std::unique_ptr<SpiffeId> parsed;
    try {
        parsed = std::make_unique<SpiffeId>(uri);
    } catch (const std::system_error&) {
        raise(EINVAL, "Not a SPIFFE ID of rawstor: " + uri);
    }
    const SpiffeId& id = *parsed;
    std::string common_name = id.name().substr(0, 64);

    Cert ca = read_cert(join(_dir, "ca.crt"));
    Key ca_key = read_key(join(_dir, "ca.key"));
    if (X509_check_private_key(ca.get(), ca_key.get()) != 1) {
        fail("The CA key does not match the CA certificate", EINVAL);
    }

    Key key = new_key();
    Cert cert = build(
        Profile{false, common_name, uri}, key.get(), ca.get(), ca_key.get(),
        validity
    );
    // The key first: a process that reads the pair in between sees the new
    // key with the old certificate, which it refuses and retries.
    write_key(key_file, key.get());
    write_cert(cert_file, cert.get());
}

void Ca::renew(
    const std::string& cert_file, const std::string& key_file,
    std::chrono::seconds validity
) const {
    ERR_clear_error();
    Cert old = read_cert(cert_file);
    Cert ca = read_cert(join(_dir, "ca.crt"));
    Key ca_key = read_key(join(_dir, "ca.key"));
    // Not a certificate of this CA: whoever holds it must go through issue.
    if (X509_check_issued(ca.get(), old.get()) != X509_V_OK ||
        X509_verify(old.get(), ca_key.get()) != 1) {
        ERR_clear_error();
        raise(EINVAL, cert_file + " was not issued by this CA");
    }
    issue(identity_of(old.get(), cert_file), validity, cert_file, key_file);
}

} // namespace rawtls
