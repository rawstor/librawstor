#ifndef RAWSTORSTD_GPP_HPP
#define RAWSTORSTD_GPP_HPP

#include <system_error>

#include <cerrno>


#define _RAWSTOR_STRINGIZE_DETAIL(x) #x
#define _RAWSTOR_STRINGIZE(x) _RAWSTOR_STRINGIZE_DETAIL(x)


#define RAWSTOR_THROW_SYSTEM_ERROR(err) \
    throw std::system_error( \
        (err), std::generic_category(), \
        __FILE__ ":" _RAWSTOR_STRINGIZE(__LINE__))


#define RAWSTOR_THROW_ERRNO() \
    do { \
        int err = errno; \
        errno = 0; \
        RAWSTOR_THROW_SYSTEM_ERROR(err); \
    } while (0)


#endif // RAWSTORSTD_GPP_HPP
