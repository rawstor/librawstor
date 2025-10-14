#ifndef RAWSTORIO_CALLBACK_HPP
#define RAWSTORIO_CALLBACK_HPP

#include <rawstor/io_event.h>

namespace rawstor {
namespace io {


class Callback {
    public:
        Callback() {}
        Callback(const Callback &) = delete;
        Callback(Callback &&) = delete;
        virtual ~Callback() {}
        Callback& operator=(const Callback &) = delete;
        Callback& operator=(Callback &&) = delete;
        virtual void operator()(RawstorIOEvent *event) = 0;
};


}} // rawstor::io

#endif // RAWSTORIO_CALLBACK_HPP
