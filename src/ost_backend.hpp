#ifndef RAWSTOR_OST_BACKEND_HPP
#define RAWSTOR_OST_BACKEND_HPP

#include "remote_backend.hpp"

namespace rawstor {
namespace ost {

class Backend final : public remote::Backend {
public:
    using remote::Backend::Backend;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_BACKEND_HPP
