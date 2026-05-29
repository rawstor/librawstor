#ifndef RAWSTD_GPP_HPP
#define RAWSTD_GPP_HPP

#include <system_error>

#include <cerrno>

#define _RAWSTD_STRINGIZE_DETAIL(x) #x
#define _RAWSTD_STRINGIZE(x) _RAWSTD_STRINGIZE_DETAIL(x)

#define RAWSTD_THROW_SYSTEM_ERROR(err)                                         \
    throw std::system_error(                                                   \
        (err), std::generic_category(),                                        \
        __FILE__ ":" _RAWSTD_STRINGIZE(__LINE__)                               \
    )

#define RAWSTD_THROW_ERRNO()                                                   \
    do {                                                                       \
        int err = errno;                                                       \
        errno = 0;                                                             \
        RAWSTD_THROW_SYSTEM_ERROR(err);                                        \
    } while (0)

#endif // RAWSTD_GPP_HPP
