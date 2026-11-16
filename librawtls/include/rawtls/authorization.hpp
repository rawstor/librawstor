#ifndef RAWTLS_AUTHORIZATION_HPP
#define RAWTLS_AUTHORIZATION_HPP

#include <rawstor/protocol.h>
#include <rawtls/transport.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace rawtls {

// A closed table: zero means the command is not a tenant member operation.
uint32_t member_right(RawstorCommandType command, uint64_t flags = 0);
bool provider_member(Role role, RawstorCommandType command);
uint32_t role_rights(uint32_t role);

// Ed25519 signing key and PEM public-key bundle. Keys are read per operation,
// allowing overlap during rotation; a key ID is SHA-256 of its raw public key.
RawstorCapability
sign_capability(RawstorCapability token, const std::string& key_file);
void verify_capability(
    const RawstorCapability& token, const std::string& keys_file,
    const Transport& connection, uint64_t now
);

// One connection's verified capability. The signed scope is checked for every
// command; cryptography is done only when installing/renewing the token.
class Authorization final {
    RawstorCapability _token{};
    bool _installed = false;

public:
    void renew(const RawstorCapability& token, const Transport& connection);
    int check(
        const Transport& connection, RawstorCommandType command,
        const uint8_t* id, uint64_t offset, const uint8_t* version,
        uint64_t flags = 0
    ) const;
    const RawstorCapability* token() const noexcept {
        return _installed ? &_token : nullptr;
    }
};

} // namespace rawtls
#endif
