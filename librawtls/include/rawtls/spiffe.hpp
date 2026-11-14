#ifndef RAWTLS_SPIFFE_HPP
#define RAWTLS_SPIFFE_HPP

#include <string>

namespace rawtls {

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
 *   spiffe://<trust_domain>/mds/<name>
 *   spiffe://<trust_domain>/admin/<name>
 *   spiffe://<trust_domain>/tenant/<tenant_id>/client/<name>
 *
 * The trust domain is lowercase letters, digits, '.', '-' and '_' (at most 255
 * bytes), a path segment is letters, digits, '.', '-' and '_' (never "." or
 * ".."), the whole ID is at most 2048 bytes, and `ost_id` and `tenant_id` are
 * non-nil UUIDs in their canonical lowercase text form.
 */
struct SpiffeId {
    // The ID as it was parsed.
    std::string uri;
    std::string trust_domain;
    Role role;
    // The tenant of a client, empty for every other role.
    std::string tenant;
    // The OST id of an ost, the name of every other role.
    std::string name;

    // Throws std::system_error(EINVAL) if `uri` is not one of the shapes
    // above.
    static SpiffeId parse(const std::string& uri);

    // True for the roles that may serve a connection: an OST or an MDS.
    bool is_server() const noexcept {
        return role == Role::ost || role == Role::mds;
    }
};

} // namespace rawtls

#endif // RAWTLS_SPIFFE_HPP
