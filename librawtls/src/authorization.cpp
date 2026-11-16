#include <rawstor/pki.h>
#include <rawtls/authorization.hpp>

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <rawstd/uuid.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <memory>
#include <sstream>
#include <system_error>

namespace {
// UUID 52d3fc80-54f7-49a5-932b-28eb45da706f, represented below its 2.25 arc.
constexpr const char* policy_oid =
    "2.25.110097391626234565544022595913142399087";
constexpr size_t max_objects = 128;

[[noreturn]] void fail(int error) {
    throw std::system_error(
        error, std::generic_category(), "Certificate permissions"
    );
}

std::string encode(const rawtls::Permissions& policy) {
    if (policy.role < RAWSTOR_ROLE_READER ||
        policy.role > RAWSTOR_ROLE_MANAGER ||
        policy.objects.size() > max_objects)
        fail(EINVAL);
    std::string text =
        "rawstor-access-v1\n" + std::to_string(policy.role) + "\n";
    for (const auto& [object, mask] : policy.objects) {
        RawstdUUID id{};
        RawstdUUIDString canonical;
        if (rawstd_uuid_from_string(&id, object.c_str()) < 0 ||
            rawstd_uuid_is_nil(&id) || (mask & ~RAWSTOR_PERM_ALL))
            fail(EINVAL);
        rawstd_uuid_to_string(&id, &canonical);
        if (object != canonical)
            fail(EINVAL);
        text += object + "=" + std::to_string(mask) + "\n";
    }
    return text;
}
} // namespace

namespace rawtls {
uint32_t role_permissions(uint32_t role) {
    switch (role) {
    case RAWSTOR_ROLE_READER:
        return RAWSTOR_PERM_READ;
    case RAWSTOR_ROLE_WRITER:
        return RAWSTOR_PERM_READ | RAWSTOR_PERM_WRITE | RAWSTOR_PERM_DISCARD;
    case RAWSTOR_ROLE_MANAGER:
        return RAWSTOR_PERM_ALL;
    case 0:
        return 0;
    default:
        fail(EINVAL);
    }
}
uint32_t member_permission(RawstorCommandType command, uint64_t flags) {
    switch (command) {
    case RAWSTOR_CMD_SET_OBJECT:
        return flags & RAWSTOR_READONLY ? RAWSTOR_PERM_READ
                                        : RAWSTOR_PERM_WRITE;
    case RAWSTOR_CMD_READ:
    case RAWSTOR_CMD_META:
    case RAWSTOR_CMD_LIST_VERSIONS:
    case RAWSTOR_CMD_LIST:
        return RAWSTOR_PERM_READ;
    case RAWSTOR_CMD_WRITE:
    case RAWSTOR_CMD_FLUSH:
    case RAWSTOR_CMD_LEAVE:
    case RAWSTOR_CMD_SYNC_PREPARE:
    case RAWSTOR_CMD_SYNC_ACCEPT:
        return RAWSTOR_PERM_WRITE;
    case RAWSTOR_CMD_DISCARD:
        return RAWSTOR_PERM_DISCARD;
    case RAWSTOR_CMD_WRITE_ZEROES:
        return flags & RAWSTOR_FLAG_UNMAP ? RAWSTOR_PERM_DISCARD
                                          : RAWSTOR_PERM_WRITE;
    case RAWSTOR_CMD_ALLOCATE:
    case RAWSTOR_CMD_RELEASE:
    case RAWSTOR_CMD_CREATE_VERSION:
    case RAWSTOR_CMD_FREEZE:
    case RAWSTOR_CMD_THAW:
        return RAWSTOR_PERM_MANAGE;
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

uint32_t Permissions::mask(const uint8_t* object) const {
    uint32_t result = role_permissions(role);
    if (object && !objects.empty()) {
        RawstdUUID id{};
        RawstdUUIDString text;
        memcpy(id.bytes, object, sizeof(id.bytes));
        rawstd_uuid_to_string(&id, &text);
        auto it = objects.find(text);
        if (it != objects.end())
            result &= it->second;
    }
    return result;
}

Permissions certificate_permissions(X509* cert) {
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid(
        OBJ_txt2obj(policy_oid, 1), ASN1_OBJECT_free
    );
    if (!oid)
        fail(EIO);
    int index = X509_get_ext_by_OBJ(cert, oid.get(), -1);
    if (index < 0)
        return {};
    if (X509_get_ext_by_OBJ(cert, oid.get(), index) >= 0)
        fail(EINVAL);
    X509_EXTENSION* extension = X509_get_ext(cert, index);
    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(extension);
    int size = ASN1_STRING_length(data);
    if (size <= 0 || size > 8192)
        fail(EINVAL);
    const unsigned char* first = ASN1_STRING_get0_data(data);
    const unsigned char* cursor = first;
    std::unique_ptr<ASN1_UTF8STRING, decltype(&ASN1_UTF8STRING_free)> value(
        d2i_ASN1_UTF8STRING(nullptr, &cursor, size), ASN1_UTF8STRING_free
    );
    if (!value || cursor != first + size)
        fail(EINVAL);
    std::string text(
        reinterpret_cast<const char*>(ASN1_STRING_get0_data(value.get())),
        ASN1_STRING_length(value.get())
    );
    std::istringstream lines(text);
    std::string line;
    if (!std::getline(lines, line) || line != "rawstor-access-v1")
        fail(EINVAL);
    Permissions result;
    if (!std::getline(lines, line) || line.size() != 1 || line[0] < '1' ||
        line[0] > '3')
        fail(EINVAL);
    result.role = line[0] - '0';
    while (std::getline(lines, line)) {
        if (result.objects.size() >= max_objects || line.size() < 38 ||
            line[36] != '=')
            fail(EINVAL);
        std::string object = line.substr(0, 36), mask = line.substr(37);
        if (mask.empty() || mask.size() > 2 ||
            mask.find_first_not_of("0123456789") != std::string::npos)
            fail(EINVAL);
        unsigned int parsed_mask = static_cast<unsigned int>(std::stoul(mask));
        if (!result.objects.emplace(object, parsed_mask).second)
            fail(EINVAL);
    }
    // Re-encoding enforces canonical UUIDs, masks, order, and a final newline.
    if (encode(result) != text)
        fail(EINVAL);
    return result;
}

void certificate_permissions(X509* cert, const Permissions& policy) {
    if (!policy.role && policy.objects.empty())
        return;
    std::string text = encode(policy);
    std::unique_ptr<ASN1_UTF8STRING, decltype(&ASN1_UTF8STRING_free)> value(
        ASN1_UTF8STRING_new(), ASN1_UTF8STRING_free
    );
    if (!value || ASN1_STRING_set(value.get(), text.data(), text.size()) != 1)
        fail(EIO);
    int size = i2d_ASN1_UTF8STRING(value.get(), nullptr);
    if (size <= 0)
        fail(EIO);
    std::vector<unsigned char> der(size);
    unsigned char* cursor = der.data();
    if (i2d_ASN1_UTF8STRING(value.get(), &cursor) != size)
        fail(EIO);
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid(
        OBJ_txt2obj(policy_oid, 1), ASN1_OBJECT_free
    );
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> data(
        ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free
    );
    if (!oid || !data ||
        ASN1_OCTET_STRING_set(data.get(), der.data(), der.size()) != 1)
        fail(EIO);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
        X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0, data.get()),
        X509_EXTENSION_free
    );
    if (!extension || X509_add_ext(cert, extension.get(), -1) != 1)
        fail(EIO);
}

int Authorization::owner(
    const Transport& connection, const uint8_t* tenant
) const {
    auto peer = connection.peer();
    if (!peer || peer->role() != Role::client)
        return 0;
    RawstdUUID expected{};
    if (rawstd_uuid_from_string(&expected, peer->tenant().c_str()) < 0 ||
        memcmp(expected.bytes, tenant, 16))
        return ENOENT;
    return 0;
}

int Authorization::check(
    const Transport& connection, RawstorCommandType command, const uint8_t* id,
    uint64_t, const uint8_t* version, uint64_t flags
) const {
    auto peer = connection.peer();
    if (!peer)
        return 0;
    if (connection.peer_expiry() <= static_cast<uint64_t>(time(nullptr)))
        return EACCES;
    if (peer->role() != Role::client)
        return provider_member(peer->role(), command) ? 0 : EACCES;
    uint32_t required = member_permission(command, flags),
             mask = peer->permissions().mask(id);
    if (!required || (mask & required) != required)
        return EACCES;
    if ((command == RAWSTOR_CMD_FREEZE || command == RAWSTOR_CMD_THAW) &&
        !(mask & RAWSTOR_PERM_MANAGE))
        return EACCES;
    // Snapshots are immutable, even when the certificate grants live writes.
    RawstdUUID selected{};
    if (version)
        memcpy(selected.bytes, version, sizeof(selected.bytes));
    if (!rawstd_uuid_is_nil(&selected) &&
        (required & (RAWSTOR_PERM_WRITE | RAWSTOR_PERM_DISCARD)))
        return EACCES;
    return 0;
}
} // namespace rawtls
