#ifndef RAWSTOR_SOCKET_HPP
#define RAWSTOR_SOCKET_HPP

#include "config.h"

#ifdef RAWSTOR_ENABLE_OST
#include "socket_ost.hpp"
#else
#include "socket_file.hpp"
#endif

#endif // RAWSTOR_SOCKET_HPP
