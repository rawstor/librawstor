#ifndef RAWTLS_CA_HPP
#define RAWTLS_CA_HPP

#include <rawtls/spiffe.hpp>

#include <chrono>
#include <string>

namespace rawtls {

/*
 * A small certificate authority for installations that have none: a directory
 * with the CA certificate (`ca.crt`, what every process lists in
 * RAWSTOR_TLS_CA), its private key (`ca.key`, readable by its owner only, and
 * the one file that never leaves the machine that issues certificates) and the
 * trust domain of the cluster it serves (`trust_domain`).
 *
 * It issues what rawtls::Context expects of a process: an EC P-256 key and a
 * certificate with exactly one URI SAN, the SPIFFE ID, the key usage
 * `digitalSignature` and the extended key usages `serverAuth` and
 * `clientAuth`. The ID is built from a role and a name, and always in the trust
 * domain of the CA, so a certificate cannot be made for another cluster.
 * Certificates are short-lived: the caller says for how long.
 *
 * Every failure is a std::system_error: EEXIST for an `init` over an existing
 * CA, EINVAL for a bad trust domain, name or validity or a certificate this CA
 * did not issue, ENOENT for a CA that is not there, other values from the file
 * system.
 */
class CA final {
private:
    std::string _dir;
    std::string _trust_domain;

    std::string issue_id(
        const std::string& id, std::chrono::seconds validity,
        const std::string& cert_file, const std::string& key_file
    ) const;

public:
    // Creates the directory (mode 0700) with a new CA for `trust_domain` in
    // it, valid for `validity`. Refuses to touch a directory that already has
    // a CA.
    static void init(
        const std::string& dir, const std::string& trust_domain,
        std::chrono::seconds validity
    );

    // Opens the CA in `dir`; throws if it is not there or not readable.
    explicit CA(const std::string& dir);

    const std::string& trust_domain() const noexcept { return _trust_domain; }

    // The CA certificate: what a process lists as its CA.
    std::string ca_file() const;

    /*
     * Issues a certificate for an identity of `role` with a new key, writing
     * both as PEM and replacing what is there; the key is written with mode
     * 0600. Returns the SPIFFE ID.
     *
     * `name` is the OST id of an ost and the MDS id of an mds, UUIDs that are
     * made if empty, the name of an admin, and the name of a client of the
     * tenant `tenant`, which only a client has. The shapes are those of
     * SpiffeId.
     *
     * Both files are written aside and then renamed over the old ones, so a
     * failure to write leaves the old pair as it was.
     */
    std::string issue(
        Role role, const std::string& tenant, const std::string& name,
        std::chrono::seconds validity, const std::string& cert_file,
        const std::string& key_file
    ) const;

    // Issues a new certificate and key for the identity of `cert_file`, which
    // this CA must have issued, over the same files. Used before the old one
    // expires; a process picks the new one up on SIGHUP. Returns the SPIFFE
    // ID.
    std::string renew(
        const std::string& cert_file, const std::string& key_file,
        std::chrono::seconds validity
    ) const;
};

} // namespace rawtls

#endif // RAWTLS_CA_HPP
