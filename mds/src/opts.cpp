#include <mds/opts.hpp>

#include <rawstd/env.h>
#include <rawstd/gpp.hpp>

#include <cerrno>
#include <climits>

namespace rawstor {
namespace mdsserver {

Opts Opts::from_env() {
    Opts opts;
    // All checked before failing, so one run reports every invalid one.
    int heartbeat = rawstd_env_uint(
        "RAWSTOR_MDS_OPTS_HEARTBEAT_INTERVAL", opts.heartbeat_interval, 1,
        UINT_MAX / 3, &opts.heartbeat_interval
    );
    int interval = rawstd_env_uint(
        "RAWSTOR_MDS_OPTS_INFO_INTERVAL", opts.info_interval, 1, UINT_MAX,
        &opts.info_interval
    );
    int refresh = rawstd_env_uint(
        "RAWSTOR_MDS_OPTS_INFO_REFRESH_DELAY", opts.info_refresh_delay, 0,
        UINT_MAX, &opts.info_refresh_delay
    );
    if (heartbeat != 0 || interval != 0 || refresh != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return opts;
}

} // namespace mdsserver
} // namespace rawstor
