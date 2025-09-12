#ifndef RAWSTORSTD_GPP_HPP
#define RAWSTORSTD_GPP_HPP

#include <system_error>


#define RAWSTOR_STRINGIZE_DETAIL(x) #x
#define RAWSTOR_STRINGIZE(x) RAWSTOR_STRINGIZE_DETAIL(x)

#define RAWSTOR_THROW_ERRNO(err) \
    throw std::system_error( \
        err, std::generic_category(), \
        __FILE__ ":" RAWSTOR_STRINGIZE(__LINE__))


#endif // RAWSTORSTD_GPP_HPP
