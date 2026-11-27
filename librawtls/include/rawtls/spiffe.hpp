#ifndef RAWTLS_SPIFFE_HPP
#define RAWTLS_SPIFFE_HPP

#include <rawstd/uri.hpp>

#include <cstdint>
#include <map>
#include <string>

namespace rawtls {

// Certificate policy: the account role supplies defaults; object masks override
// them.
struct Permissions {
    uint32_t role = 0;
    std::map<std::string, uint32_t> objects;

    uint32_t mask(const uint8_t* object = nullptr) const;
};

enum class Type {
    ost,
    mds,
    admin,
    account,
};

/*
 * The identity of a peer: a SPIFFE ID in one of the four shapes rawstor uses,
 * `spiffe://<trust_domain>/<cert_type>/<cert_id>[/client/<client_id>]`.
 *
 *   spiffe://<trust_domain>/ost/<cert_id>
 *   spiffe://<trust_domain>/mds/<cert_id>
 *   spiffe://<trust_domain>/admin/<cert_id>
 *   spiffe://<trust_domain>/account/<cert_id>/client/<client_id>
 *
 * The trust domain is lowercase letters, digits, '.', '-' and '_' (at most 255
 * bytes), a path segment is letters, digits, '.', '-' and '_' (never "." or
 * ".."), the whole ID is at most 2048 bytes, and the `cert_id` of an ost, an
 * mds and an account (the OST id, the MDS id and the account id) is a non-nil
 * UUID in its canonical lowercase text form. There is no user information,
 * port, query or fragment.
 */
class SpiffeId final {
private:
    rawstd::URI _uri;
    Type _type;
    std::string _cert_id;
    std::string _client_id;
    Permissions _permissions;

public:
    // Throws std::system_error(EINVAL) if `uri` is not one of the shapes
    // above.
    explicit SpiffeId(const std::string& uri);

    // The ID as it was parsed.
    const rawstd::URI& uri() const noexcept { return _uri; }

    const std::string& trust_domain() const noexcept { return _uri.hostname(); }

    Type type() const noexcept { return _type; }

    // The segment after the type: the OST id of an ost, the MDS id of an mds,
    // the name of an admin and the account id of an account.
    const std::string& cert_id() const noexcept { return _cert_id; }

    // The client of an account, empty for every other type.
    const std::string& client_id() const noexcept { return _client_id; }

    const Permissions& permissions() const noexcept { return _permissions; }

    void permissions(Permissions value) { _permissions = std::move(value); }

    // True for the types that may serve a connection: an OST or an MDS.
    bool is_server() const noexcept {
        return _type == Type::ost || _type == Type::mds;
    }
};

} // namespace rawtls

#endif // RAWTLS_SPIFFE_HPP
