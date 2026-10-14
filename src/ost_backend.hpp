#ifndef RAWSTOR_OST_BACKEND_HPP
#define RAWSTOR_OST_BACKEND_HPP

#include "wire_backend.hpp"

namespace rawstor {
namespace ost {

class Backend final : public wire::Backend {
public:
    using wire::Backend::Backend;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_BACKEND_HPP
