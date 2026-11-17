#ifndef RAWSTOR_TESTS_OWNER_HPP
#define RAWSTOR_TESTS_OWNER_HPP

#include <rawstor/location.h>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <string>

// Accounts (docs/accounts.md) as the tests need them: owners to create objects
// for and addresses naming one.
namespace rawstor {
namespace tests {

// The account that owns what is created without naming one.
inline RawstdUUID default_owner() {
    RawstdUUID id;
    rawstd_uuid_from_string(&id, RAWSTOR_DEFAULT_ACCOUNT);
    return id;
}

// The account `uri` names as user information, the nil UUID when it names none.
inline RawstdUUID named_owner(const rawstd::URI& uri) {
    RawstdUUID id{};
    if (!uri.username().empty()) {
        rawstd_uuid_from_string(&id, uri.username().c_str());
    }
    return id;
}

// `uri` with `account` as its user information, none for the nil UUID.
inline rawstd::URI
with_account(const rawstd::URI& uri, const RawstdUUID& account) {
    std::string ret = uri.scheme() + "://";
    if (!rawstd_uuid_is_nil(&account)) {
        RawstdUUIDString text;
        rawstd_uuid_to_string(&account, &text);
        ret += std::string(text) + "@";
    }
    ret += uri.host() + uri.path().str();
    return rawstd::URI(ret);
}

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_OWNER_HPP
