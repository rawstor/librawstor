#include <rawstor/pki.h>

#include <rawtls/ca.hpp>

#include <cerrno>
#include <chrono>
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

} // namespace

extern "C" {

int rawstor_pki_init(
    const char* dir, const char* name, unsigned long validity
) {
    return guarded([&] { rawtls::CA::init(dir, name, seconds(validity)); });
}

int rawstor_pki_issue(
    const char* dir, const char* identity, unsigned long validity,
    const char* cert_file, const char* key_file
) {
    return guarded([&] {
        rawtls::CA(dir).issue(identity, seconds(validity), cert_file, key_file);
    });
}

int rawstor_pki_renew(
    const char* dir, const char* cert_file, const char* key_file,
    unsigned long validity
) {
    return guarded([&] {
        rawtls::CA(dir).renew(cert_file, key_file, seconds(validity));
    });
}

const char* rawstor_pki_error(void) {
    return last_error.c_str();
}

} // extern "C"
