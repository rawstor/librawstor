#include <rawtls/authorization.hpp>
#include <rawtls/ca.hpp>

#include <rawtls/spiffe.hpp>

#include <rawstd/uuid.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
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
    std::chrono::seconds validity, const rawtls::Permissions& permissions = {}
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
    }
    // The SPIFFE ID of a process, or the trust domain of a CA.
    add_extension(
        raw, signer, NID_subject_alt_name, ("URI:" + profile.uri).c_str()
    );
    rawtls::certificate_permissions(raw, permissions);
    check(
        X509_sign(raw, issuer_key != nullptr ? issuer_key : key, EVP_sha256()) >
            0,
        "Certificate signature"
    );
    return cert;
}

// A file written aside, next to the one it is going to replace, and renamed
// over it by commit(). The name of the temporary file is made by mkstemp(),
// which creates it exclusively, so a file or a symlink that somebody put in the
// directory beforehand is never written through; rename() replaces a symlink
// at `file` instead of following it. What is not committed is removed.
class Staged final {
private:
    std::string _file;
    std::string _tmp;

public:
    Staged() = default;

    // `mode` is the mode of the new file: a key must not end up with more than
    // asked, whatever the umask is.
    template <typename Write>
    Staged(const std::string& file, mode_t mode, Write write) : _file(file) {
        std::filesystem::path path(file);
        std::filesystem::path dir = path.parent_path();
        if (dir.empty()) {
            dir = ".";
        }
        std::string pattern =
            (dir / ("." + path.filename().string() + ".XXXXXX")).string();
        int fd = mkostemp(pattern.data(), O_CLOEXEC);
        if (fd < 0) {
            raise(errno, "Cannot write " + file);
        }
        _tmp = pattern;
        if (fchmod(fd, mode) != 0) {
            int errsv = errno;
            close(fd);
            raise(errsv, "Cannot write " + file);
        }
        FILE* f = fdopen(fd, "w");
        if (f == nullptr) {
            int errsv = errno;
            close(fd);
            raise(errsv, "Cannot write " + file);
        }
        errno = 0;
        bool ok = write(f) && fflush(f) == 0 && fsync(fileno(f)) == 0;
        int errsv = ok ? 0 : (errno != 0 ? errno : EIO);
        if (fclose(f) != 0 && ok) {
            ok = false;
            errsv = errno;
        }
        if (!ok) {
            raise(errsv, "Cannot write " + file);
        }
    }

    Staged(Staged&& other) noexcept :
        _file(std::move(other._file)),
        _tmp(std::move(other._tmp)) {
        other._tmp.clear();
    }

    Staged& operator=(Staged&&) = delete;
    Staged(const Staged&) = delete;
    Staged& operator=(const Staged&) = delete;

    ~Staged() {
        if (!_tmp.empty()) {
            unlink(_tmp.c_str());
        }
    }

    void commit() {
        if (rename(_tmp.c_str(), _file.c_str()) != 0) {
            raise(errno, "Cannot write " + _file);
        }
        _tmp.clear();
    }

    // Keep the previous key beside its destination until the certificate is
    // published too. On failure restore the original directory entry, including
    // a symlink, rather than writing through it.
    void commit_pair(Staged& cert) {
        Staged previous(_file, 0600, [](FILE*) { return true; });
        if (unlink(previous._tmp.c_str()) != 0) {
            raise(errno, "Cannot prepare backup of " + _file);
        }
        bool existed = link(_file.c_str(), previous._tmp.c_str()) == 0;
        if (!existed && errno != ENOENT) {
            raise(errno, "Cannot preserve " + _file);
        }
        try {
            commit();
            cert.commit();
        } catch (...) {
            int res = existed ? rename(previous._tmp.c_str(), _file.c_str())
                              : unlink(_file.c_str());
            if (res != 0 && (existed || errno != ENOENT)) {
                int errsv = errno;
                std::string backup = previous._tmp;
                // Leave the backup available for recovery if restoration fails.
                previous._tmp.clear();
                raise(errsv, "Cannot restore " + _file + "; backup: " + backup);
            }
            throw;
        }
    }
};

Staged stage_cert(const std::string& file, X509* cert) {
    return Staged(file, 0644, [&](FILE* f) {
        return PEM_write_X509(f, cert) == 1;
    });
}

Staged stage_key(const std::string& file, EVP_PKEY* key) {
    return Staged(file, 0600, [&](FILE* f) {
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

// Signature verification needs only the issuer's public certificate.
bool signed_by(X509* cert, X509* ca) {
    Key public_key(X509_get_pubkey(ca));
    check(public_key != nullptr, "CA public key");
    bool ok = X509_check_issued(ca, cert) == X509_V_OK &&
              X509_verify(cert, public_key.get()) == 1;
    ERR_clear_error();
    return ok;
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
    // The parents the way `mkdir -p` makes them; the directory of the CA is
    // the one that holds its key, so only it is private.
    std::filesystem::path parent = std::filesystem::path(dir).parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            raise(ec.value(), "Cannot create " + parent.string());
        }
    }
    if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
        raise(errno, "Cannot create " + dir);
    }
}

} // namespace

namespace rawtls {

namespace {

// Only a name that makes a SPIFFE ID of rawstor in this trust domain.
void check_trust_domain(const std::string& trust_domain) {
    try {
        static_cast<void>(SpiffeId("spiffe://" + trust_domain + "/admin/x"));
    } catch (const std::system_error&) {
        raise(EINVAL, "Not a trust domain of rawstor: " + trust_domain);
    }
}

std::string new_id() {
    RawstdUUID id;
    int res = rawstd_uuid7_init(&id);
    if (res < 0) {
        raise(-res, "Cannot generate an id");
    }
    RawstdUUIDString text;
    rawstd_uuid_to_string(&id, &text);
    return text;
}

} // namespace

void CA::init(
    const std::string& dir, const std::string& trust_domain,
    std::chrono::seconds validity
) {
    ERR_clear_error();
    check_trust_domain(trust_domain);
    make_dir(dir);
    if (access(join(dir, "ca.key").c_str(), F_OK) == 0 ||
        access(join(dir, "ca.crt").c_str(), F_OK) == 0) {
        raise(EEXIST, dir + " has a CA already");
    }
    Key key = new_key();
    Cert cert = build(
        Profile{true, "rawstor CA", "spiffe://" + trust_domain}, key.get(),
        nullptr, nullptr, validity
    );
    Staged key_file = stage_key(join(dir, "ca.key"), key.get());
    Staged cert_file = stage_cert(join(dir, "ca.crt"), cert.get());
    // Publish the certificate last and remove the key on failure so
    // initialization can be retried.
    key_file.commit();
    try {
        cert_file.commit();
    } catch (...) {
        unlink(join(dir, "ca.key").c_str());
        throw;
    }
}

CA::CA(const std::string& dir) : _dir(dir) {
    ERR_clear_error();
    if (access(join(dir, "ca.crt").c_str(), R_OK) != 0) {
        raise(errno, "No CA in " + dir);
    }
    // The trust domain is the one URI SAN of the CA certificate.
    const std::string file = join(dir, "ca.crt");
    const std::string scheme = "spiffe://";
    std::string uri = identity_of(read_cert(file).get(), file);
    if (uri.compare(0, scheme.size(), scheme) != 0) {
        raise(EINVAL, file + " has not a trust domain");
    }
    _trust_domain = uri.substr(scheme.size());
    check_trust_domain(_trust_domain);
}

std::string CA::ca_file() const {
    return join(_dir, "ca.crt");
}

std::string CA::issue_id(
    const std::string& id, std::chrono::seconds validity,
    const std::string& cert_file, const std::string& key_file,
    const Permissions& permissions
) const {
    // The shape is the one a process is going to be checked against. The
    // identity is the SAN alone; the subject only has to be something to read
    // in a listing, and a common name is at most 64 bytes.
    std::unique_ptr<SpiffeId> parsed;
    try {
        parsed = std::make_unique<SpiffeId>(id);
    } catch (const std::system_error&) {
        raise(EINVAL, "Not a SPIFFE ID of rawstor: " + id);
    }
    if (parsed->trust_domain() != _trust_domain) {
        raise(
            EINVAL,
            id + " is not in the trust domain " + _trust_domain + " of this CA"
        );
    }
    if (parsed->type() != Type::client &&
        (permissions.role || !permissions.objects.empty())) {
        raise(EINVAL, "Only a client has permissions");
    }
    std::string common_name = parsed->name().substr(0, 64);

    Cert ca = read_cert(join(_dir, "ca.crt"));
    Key ca_key = read_key(join(_dir, "ca.key"));
    if (X509_check_private_key(ca.get(), ca_key.get()) != 1) {
        fail("The CA key does not match the CA certificate", EINVAL);
    }

    Key key = new_key();
    Cert cert = build(
        Profile{false, common_name, id}, key.get(), ca.get(), ca_key.get(),
        validity, permissions
    );
    Staged staged_key = stage_key(key_file, key.get());
    Staged staged_cert = stage_cert(cert_file, cert.get());
    staged_key.commit_pair(staged_cert);
    return id;
}

std::string CA::issue(
    Type type, const std::string& account, const std::string& name,
    std::chrono::seconds validity, const std::string& cert_file,
    const std::string& key_file, const Permissions& permissions
) const {
    ERR_clear_error();
    std::string id = "spiffe://" + _trust_domain;
    if (type != Type::client && !account.empty()) {
        raise(EINVAL, "Only a client has an account");
    }
    switch (type) {
    case Type::ost:
    case Type::mds:
        id += (type == Type::ost ? "/ost/" : "/mds/") +
              (name.empty() ? new_id() : name);
        break;
    case Type::admin:
        if (name.empty()) {
            raise(EINVAL, "A name is required");
        }
        id += "/admin/" + name;
        break;
    case Type::client:
        if (account.empty() || name.empty()) {
            raise(EINVAL, "A client needs an account and a name");
        }
        id += "/account/" + account + "/client/" + name;
        break;
    }
    return issue_id(id, validity, cert_file, key_file, permissions);
}

std::string CA::renew(
    const std::string& cert_file, const std::string& key_file,
    std::chrono::seconds validity
) const {
    ERR_clear_error();
    // Not a certificate of this CA: whoever holds it must go through issue.
    Cert old = read_cert(cert_file);
    Cert ca = read_cert(ca_file());
    if (!signed_by(old.get(), ca.get())) {
        raise(EINVAL, cert_file + " was not issued by this CA");
    }
    return issue_id(
        identity_of(old.get(), cert_file), validity, cert_file, key_file,
        certificate_permissions(old.get())
    );
}

bool CA::issued(const std::string& cert_file) const {
    ERR_clear_error();
    Cert cert = read_cert(cert_file);
    Cert ca = read_cert(join(_dir, "ca.crt"));
    return signed_by(cert.get(), ca.get());
}

CertInfo inspect(const std::string& cert_file, const std::string& ca_file) {
    ERR_clear_error();
    Cert cert = read_cert(cert_file);
    std::string identity = identity_of(cert.get(), cert_file);
    try {
        static_cast<void>(SpiffeId(identity));
    } catch (const std::system_error&) {
        raise(EINVAL, cert_file + " does not name a process of rawstor");
    }
    struct tm tm;
    if (ASN1_TIME_to_tm(X509_get0_notAfter(cert.get()), &tm) != 1) {
        raise(EINVAL, cert_file + " has no expiry");
    }
    int issued = -1;
    if (!ca_file.empty()) {
        Cert ca = read_cert(ca_file);
        issued = signed_by(cert.get(), ca.get()) ? 1 : 0;
    }
    return CertInfo{
        identity, static_cast<long long>(timegm(&tm)), issued,
        certificate_permissions(cert.get())
    };
}

} // namespace rawtls
