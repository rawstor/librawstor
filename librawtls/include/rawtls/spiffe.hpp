#ifndef RAWTLS_SPIFFE_HPP
#define RAWTLS_SPIFFE_HPP

#include <rawstd/uri.hpp>

#include <cstdint>
#include <map>
#include <string>

namespace rawtls {

// Certificate policy: the role supplies defaults; object masks override them.
struct Permissions {
    uint32_t role = 0;
    std::map<std::string, uint32_t> objects;

    uint32_t mask(const uint8_t* object = nullptr) const;
};

enum class Role {
    ost,
    mds,
    admin,
    client,
};

/*
 * The identity of a peer: a SPIFFE ID in one of the four shapes rawstor uses.
 *
 *   spiffe://<trust_domain>/ost/<ost_id>
 *   spiffe://<trust_domain>/mds/<mds_id>
 *   spiffe://<trust_domain>/admin/<name>
 *   spiffe://<trust_domain>/tenant/<tenant_id>/client/<name>
 *
 * The trust domain is lowercase letters, digits, '.', '-' and '_' (at most 255
 * bytes), a path segment is letters, digits, '.', '-' and '_' (never "." or
 * ".."), the whole ID is at most 2048 bytes, and `ost_id`, `mds_id` and
 * `tenant_id` are non-nil UUIDs in their canonical lowercase text form. There
 * is no user information, port, query or fragment.
 */
class SpiffeId final {
private:
    rawstd::URI _uri;
    Role _role;
    std::string _tenant;
    std::string _name;
    Permissions _permissions;

public:
    // Throws std::system_error(EINVAL) if `uri` is not one of the shapes
    // above.
    explicit SpiffeId(const std::string& uri);

    // The ID as it was parsed.
    const rawstd::URI& uri() const noexcept { return _uri; }

    const std::string& trust_domain() const noexcept { return _uri.hostname(); }

    Role role() const noexcept { return _role; }

    // The tenant of a client, empty for every other role.
    const std::string& tenant() const noexcept { return _tenant; }

    // The OST id of an ost, the MDS id of an mds, the name of every other role.
    const std::string& name() const noexcept { return _name; }

    const Permissions& permissions() const noexcept { return _permissions; }

    void permissions(Permissions value) { _permissions = std::move(value); }

    // True for the roles that may serve a connection: an OST or an MDS.
    bool is_server() const noexcept {
        return _role == Role::ost || _role == Role::mds;
    }
};

} // namespace rawtls

#endif // RAWTLS_SPIFFE_HPP
