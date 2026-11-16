#include <rawstor/pki.h>

#include <rawtls/ca.hpp>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <exception>
#include <new>
#include <string>
#include <system_error>

namespace {

thread_local std::string last_error;

template <typename Call>
int guarded(Call call) {
    last_error.clear();
    try {
        call();
        return 0;
    } catch (const std::system_error& e) {
        last_error = e.what();
        return -e.code().value();
    } catch (const std::bad_alloc&) {
        last_error = "Out of memory";
        return -ENOMEM;
    } catch (const std::exception& e) {
        last_error = e.what();
        return -EIO;
    }
}

std::chrono::seconds seconds(unsigned long validity) {
    // Past what a certificate can say: the CA refuses it as a bad validity.
    constexpr unsigned long max = 1UL << 40;
    return std::chrono::seconds(
        static_cast<long long>(validity > max ? max : validity)
    );
}

std::string text(const char* s) {
    return s != nullptr ? s : "";
}

void check_room(char* identity, size_t size) {
    if (identity != nullptr && size < RAWSTOR_PKI_IDENTITY_SIZE) {
        last_error = "The identity buffer is too small";
        throw std::system_error(EINVAL, std::generic_category(), last_error);
    }
}

void give(const std::string& id, char* identity) {
    if (identity != nullptr) {
        std::memcpy(identity, id.c_str(), id.size() + 1);
    }
}

} // namespace

extern "C" {

int rawstor_pki_init(
    const char* dir, const char* trust_domain, unsigned long validity
) {
    return guarded([&] {
        rawtls::CA::init(dir, trust_domain, seconds(validity));
    });
}

int rawstor_pki_issue(
    const char* dir, enum RawstorPkiRole role, const char* tenant,
    const char* name, unsigned long validity, const char* cert_file,
    const char* key_file, char* identity, size_t size
) {
    return guarded([&] {
        check_room(identity, size);
        rawtls::Role r;
        switch (role) {
        case RAWSTOR_PKI_OST:
            r = rawtls::Role::ost;
            break;
        case RAWSTOR_PKI_MDS:
            r = rawtls::Role::mds;
            break;
        case RAWSTOR_PKI_ADMIN:
            r = rawtls::Role::admin;
            break;
        case RAWSTOR_PKI_CLIENT:
            r = rawtls::Role::client;
            break;
        default:
            throw std::system_error(
                EINVAL, std::generic_category(), "Unknown role"
            );
        }
        give(
            rawtls::CA(dir).issue(
                r, text(tenant), text(name), seconds(validity), cert_file,
                key_file
            ),
            identity
        );
    });
}

int rawstor_pki_renew(
    const char* dir, const char* cert_file, const char* key_file,
    unsigned long validity, char* identity, size_t size
) {
    return guarded([&] {
        check_room(identity, size);
        give(
            rawtls::CA(dir).renew(cert_file, key_file, seconds(validity)),
            identity
        );
    });
}

const char* rawstor_pki_error(void) {
    return last_error.c_str();
}

} // extern "C"
