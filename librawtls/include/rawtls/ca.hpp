#ifndef RAWTLS_CA_HPP
#define RAWTLS_CA_HPP

#include <chrono>
#include <string>

namespace rawtls {

/*
 * A small certificate authority for installations that have none: a directory
 * with the CA certificate (`ca.crt`, what every process lists in
 * RAWSTOR_TLS_CA) and its private key (`ca.key`, readable by its owner only,
 * and the one file that never leaves the machine that issues certificates).
 *
 * It issues what rawtls::Context expects of a process: an EC P-256 key and a
 * certificate with exactly one URI SAN, the SPIFFE ID, the key usage
 * `digitalSignature` and the extended key usages `serverAuth` and
 * `clientAuth`. Certificates are short-lived: the caller says for how long.
 *
 * Every failure is a std::system_error: EEXIST for an `init` over an existing
 * CA, EINVAL for a bad ID, a bad validity or a certificate this CA did not
 * issue, ENOENT for a CA that is not there, other values from the file system.
 */
class CA final {
private:
    std::string _dir;

public:
    // Creates the directory (mode 0700) with a new CA in it, valid for
    // `validity`. Refuses to touch a directory that already has a CA.
    static void init(
        const std::string& dir, const std::string& common_name,
        std::chrono::seconds validity
    );

    // Opens the CA in `dir`; throws if it is not there or not readable.
    explicit CA(const std::string& dir);

    // The CA certificate: what a process lists as its CA.
    std::string ca_file() const;

    // Issues a certificate for the SPIFFE ID `uri` (the shape is checked with
    // SpiffeId) with a new key, writing both as PEM. An existing file is
    // replaced; the key is written with mode 0600.
    void issue(
        const std::string& uri, std::chrono::seconds validity,
        const std::string& cert_file, const std::string& key_file
    ) const;

    // Issues a new certificate and key for the identity of `cert_file`, which
    // this CA must have issued, over the same files. Used before the old one
    // expires; a process picks the new one up on SIGHUP.
    void renew(
        const std::string& cert_file, const std::string& key_file,
        std::chrono::seconds validity
    ) const;
};

} // namespace rawtls

#endif // RAWTLS_CA_HPP
