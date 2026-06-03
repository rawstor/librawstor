#include <rawstor/rawstor.h>

#include "opts.h"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uri.hpp>

#include <sys/types.h>
#include <sys/uio.h>

#include <memory>
#include <stdexcept>
#include <system_error>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int rawstor_initialize(const RawstorOpts* opts) noexcept {
    try {
        int res = 0;

        res = rawstd_logging_initialize();
        if (res) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        rawstd_info(
            "Rawstor compiled with IO queue engine: %s\n",
            rawio::Queue::engine_name().c_str()
        );

        res = rawstor_opts_initialize(opts);
        if (res) {
            rawstd_logging_terminate();
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

void rawstor_terminate() noexcept {
    rawstor_opts_terminate();
    rawstd_logging_terminate();
}
