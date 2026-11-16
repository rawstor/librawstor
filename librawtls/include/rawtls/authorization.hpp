#ifndef RAWTLS_AUTHORIZATION_HPP
#define RAWTLS_AUTHORIZATION_HPP

#include <rawstor/protocol.h>
#include <rawtls/transport.hpp>

#include <cstdint>

struct x509_st;

namespace rawtls {

uint32_t member_permission(RawstorCommandType command, uint64_t flags = 0);

bool provider_member(Role role, RawstorCommandType command);

uint32_t role_permissions(uint32_t role);

// A noncritical, UUID-based private extension containing a DER UTF8String.
// Missing policy grants no tenant access. Malformed or duplicate policy fails.
Permissions certificate_permissions(x509_st* certificate);

void certificate_permissions(x509_st* certificate, const Permissions& policy);

class Authorization final {
public:
    int check(
        const Transport& connection, RawstorCommandType command,
        const uint8_t* id, const uint8_t* version, uint64_t flags = 0
    ) const;

    int owner(const Transport& connection, const uint8_t* tenant) const;
};

} // namespace rawtls

#endif // RAWTLS_AUTHORIZATION_HPP
