#ifndef RAWSTORIO_EVENT_HPP
#define RAWSTORIO_EVENT_HPP

#include "config.h"

#ifdef RAWSTOR_WITH_LIBURING
#else
#include <rawstorio/poll_event.hpp>

namespace rawstor {
namespace io {


typedef rawstor::io::poll::Event Event;


}} // rawstor::io

#endif


#endif // RAWSTORIO_EVENT_HPP
