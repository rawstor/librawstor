#ifndef RAWSTOR_INTERNALS_HPP
#define RAWSTOR_INTERNALS_HPP

#include <rawstorio/queue.hpp>

#include <rawstorstd/socket_address.hpp>

#include <memory>


namespace rawstor {


extern rawstor::io::Queue *io_queue;


const SocketAddress& default_ost();


} // rawstor


#endif // RAWSTOR_INTERNALS_HPP
