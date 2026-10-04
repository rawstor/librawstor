#include <mds/opts.hpp>

#include <rawstd/env.h>
#include <rawstd/gpp.hpp>

#include <cerrno>
#include <climits>

namespace rawstor {
namespace mdsserver {

Opts Opts::from_env() {
    Opts opts;
    // Both checked before failing, so one run reports every invalid one.
    int interval = rawstd_env_uint(
        "RAWSTOR_MDS_OPTS_INFO_INTERVAL", opts.info_interval, 1, UINT_MAX,
        &opts.info_interval
    );
    int concurrency = rawstd_env_uint(
        "RAWSTOR_MDS_OPTS_INFO_CONCURRENCY", opts.info_concurrency, 1,
        max_info_concurrency, &opts.info_concurrency
    );
    if (interval != 0 || concurrency != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return opts;
}

} // namespace mdsserver
} // namespace rawstor
