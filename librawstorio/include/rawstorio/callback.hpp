#ifndef RAWSTORIO_CALLBACK_HPP
#define RAWSTORIO_CALLBACK_HPP

#include <rawstor/io_event.h>

namespace rawstor {
namespace io {


class Callback {
    public:
        virtual ~Callback() {}
        virtual void operator()(RawstorIOEvent *event) = 0;
};


}} // rawstor::io

#endif // RAWSTORIO_CALLBACK_HPP
