#include <rawtls/authorization.hpp>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <rawstd/uuid.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <system_error>

namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
struct CloseFile {
    void operator()(FILE* f) const noexcept { fclose(f); }
};
using File = std::unique_ptr<FILE, CloseFile>;
using Digest = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
constexpr std::array<unsigned char, 8> format{'r', 's', 't', 'r',
                                              'c', 'a', 'p', 1};
[[noreturn]] void fail(int error) {
    throw std::system_error(
        error, std::generic_category(), "Capability authorization"
    );
}
File open_file(const std::string& file) {
    File f(fopen(file.c_str(), "r"));
    if (!f)
        fail(errno);
    return f;
}
std::array<unsigned char, 32> key_id(EVP_PKEY* key) {
    if (EVP_PKEY_base_id(key) != EVP_PKEY_ED25519)
        fail(EINVAL);
    std::array<unsigned char, 32> pub{}, id{};
    size_t size = pub.size();
    unsigned int digest_size = 0;
    if (EVP_PKEY_get_raw_public_key(key, pub.data(), &size) != 1 ||
        size != pub.size() ||
        EVP_Digest(
            pub.data(), pub.size(), id.data(), &digest_size, EVP_sha256(),
            nullptr
        ) != 1 ||
        digest_size != id.size())
        fail(EIO);
    return id;
}
} // namespace

namespace rawtls {
uint32_t role_rights(uint32_t role) {
    switch (role) {
    case RAWSTOR_PRINCIPAL_READER:
        return RAWSTOR_RIGHT_READ;
    case RAWSTOR_PRINCIPAL_WRITER:
        return RAWSTOR_RIGHT_READ | RAWSTOR_RIGHT_WRITE | RAWSTOR_RIGHT_DISCARD;
    case RAWSTOR_PRINCIPAL_MANAGER:
        return RAWSTOR_RIGHT_ALL;
    default:
        fail(EINVAL);
    }
}
uint32_t member_right(RawstorCommandType command, uint64_t flags) {
    switch (command) {
    case RAWSTOR_CMD_SET_OBJECT:
        return flags & RAWSTOR_READONLY ? RAWSTOR_RIGHT_READ
                                        : RAWSTOR_RIGHT_WRITE;
    case RAWSTOR_CMD_READ:
    case RAWSTOR_CMD_META:
    case RAWSTOR_CMD_LIST_VERSIONS:
        return RAWSTOR_RIGHT_READ;
    case RAWSTOR_CMD_WRITE:
    case RAWSTOR_CMD_FLUSH:
    case RAWSTOR_CMD_LEAVE:
    case RAWSTOR_CMD_SYNC_PREPARE:
    case RAWSTOR_CMD_SYNC_ACCEPT:
        return RAWSTOR_RIGHT_WRITE;
    case RAWSTOR_CMD_DISCARD:
        return RAWSTOR_RIGHT_DISCARD;
    case RAWSTOR_CMD_WRITE_ZEROES:
        return flags & RAWSTOR_FLAG_UNMAP ? RAWSTOR_RIGHT_DISCARD
                                          : RAWSTOR_RIGHT_WRITE;
    case RAWSTOR_CMD_ALLOCATE:
    case RAWSTOR_CMD_RELEASE:
    case RAWSTOR_CMD_CREATE_VERSION:
    case RAWSTOR_CMD_FREEZE:
    case RAWSTOR_CMD_THAW:
        return RAWSTOR_RIGHT_MANAGE;
    default:
        return 0;
    }
}
bool provider_member(Role role, RawstorCommandType command) {
    switch (command) {
    case RAWSTOR_CMD_HANDSHAKE:
        return true;
    case RAWSTOR_CMD_SET_OBJECT:
    case RAWSTOR_CMD_READ:
    case RAWSTOR_CMD_META:
    case RAWSTOR_CMD_LIST_VERSIONS:
    case RAWSTOR_CMD_LIST:
    case RAWSTOR_CMD_LOCATION_INFO:
        return role == Role::admin || role == Role::mds;
    case RAWSTOR_CMD_ALLOCATE:
    case RAWSTOR_CMD_RELEASE:
    case RAWSTOR_CMD_CREATE_VERSION:
    case RAWSTOR_CMD_FREEZE:
    case RAWSTOR_CMD_THAW:
    case RAWSTOR_CMD_SET_OWNER:
        return role == Role::admin;
    default:
        return false;
    }
}
RawstorCapability
sign_capability(RawstorCapability token, const std::string& key_file) {
    auto f = open_file(key_file);
    Key key(
        PEM_read_PrivateKey(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free
    );
    if (!key)
        fail(EINVAL);
    auto id = key_id(key.get());
    memcpy(token.key_id, id.data(), id.size());
    memcpy(token.format, format.data(), format.size());
    Digest ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    size_t size = sizeof(token.signature);
    if (!ctx ||
        EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) !=
            1 ||
        EVP_DigestSign(
            ctx.get(), token.signature, &size,
            reinterpret_cast<const unsigned char*>(&token),
            offsetof(RawstorCapability, signature)
        ) != 1 ||
        size != sizeof(token.signature))
        fail(EIO);
    return token;
}
void verify_capability(
    const RawstorCapability& token, const std::string& keys_file,
    const Transport& connection, uint64_t now
) {
    if (!connection.peer() || !connection.local() ||
        connection.peer()->role() != Role::client ||
        memcmp(token.format, format.data(), format.size()) ||
        token.not_after <= now || token.rights == 0 ||
        (token.rights & ~RAWSTOR_RIGHT_ALL))
        fail(EACCES);
    RawstdUUID tenant{}, server{};
    if (rawstd_uuid_from_string(&tenant, connection.peer()->tenant().c_str()) <
            0 ||
        rawstd_uuid_from_string(&server, connection.local()->name().c_str()) <
            0 ||
        memcmp(tenant.bytes, token.tenant_id, 16) ||
        memcmp(server.bytes, token.server_id, 16))
        fail(EACCES);
    auto fingerprint = connection.fingerprint(false);
    if (CRYPTO_memcmp(
            fingerprint.data(), token.fingerprint, fingerprint.size()
        ))
        fail(EACCES);
    auto f = open_file(keys_file);
    bool verified = false;
    while (true) {
        Key key(
            PEM_read_PUBKEY(f.get(), nullptr, nullptr, nullptr), EVP_PKEY_free
        );
        if (!key)
            break;
        auto id = key_id(key.get());
        if (CRYPTO_memcmp(id.data(), token.key_id, id.size()))
            continue;
        Digest ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        verified = ctx &&
                   EVP_DigestVerifyInit(
                       ctx.get(), nullptr, nullptr, nullptr, key.get()
                   ) == 1 &&
                   EVP_DigestVerify(
                       ctx.get(), token.signature, sizeof(token.signature),
                       reinterpret_cast<const unsigned char*>(&token),
                       offsetof(RawstorCapability, signature)
                   ) == 1;
        break;
    }
    ERR_clear_error();
    if (!verified)
        fail(EACCES);
}
void Authorization::renew(
    const RawstorCapability& token, const Transport& connection
) {
    const char* keys = getenv("RAWSTOR_AUTH_KEYS");
    if (!keys || !*keys)
        fail(EACCES);
    verify_capability(
        token, keys, connection, static_cast<uint64_t>(time(nullptr))
    );
    _token = token;
    _installed = true;
}
int Authorization::check(
    const Transport& connection, RawstorCommandType command, const uint8_t* id,
    uint64_t offset, const uint8_t* version, uint64_t flags
) const {
    const SpiffeId* peer = connection.peer();
    if (!peer)
        return 0;
    if (peer->role() != Role::client)
        return provider_member(peer->role(), command) ? 0 : EACCES;
    if (!_installed ||
        connection.peer_expiry() <= static_cast<uint64_t>(time(nullptr)))
        return EACCES;
    if (id &&
        (memcmp(id, _token.object_id, 16) || offset != _token.chunk_offset))
        return ENOENT;
    // CREATE_VERSION and FREEZE name a new version/lease, not the selected
    // version.
    if (version && memcmp(version, _token.version_id, 16)) {
        const RawstdUUID live{};
        if (command != RAWSTOR_CMD_RELEASE ||
            !(_token.rights & RAWSTOR_RIGHT_MANAGE) ||
            memcmp(_token.version_id, live.bytes, sizeof(live.bytes)))
            return ENOENT;
    }
    uint32_t right = member_right(command, flags);
    if (_token.not_after <= static_cast<uint64_t>(time(nullptr)) || !right ||
        (_token.rights & right) != right)
        return EACCES;
    if ((command == RAWSTOR_CMD_FREEZE || command == RAWSTOR_CMD_THAW) &&
        !(_token.rights & RAWSTOR_RIGHT_MANAGE))
        return EACCES;
    return 0;
}
} // namespace rawtls
