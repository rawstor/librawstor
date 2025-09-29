#ifndef RAWSTORIO_QUEUE_HPP
#define RAWSTORIO_QUEUE_HPP

#include "config.h"

#ifdef RAWSTOR_WITH_LIBURING
#else
#include <rawstorio/poll_queue.hpp>

namespace rawstor {
namespace io {


typedef rawstor::io::poll::Queue Queue;


}} // rawstor::io

#endif


#endif // RAWSTORIO_QUEUE_HPP
