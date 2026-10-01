#ifndef RAWSTOR_MDS_OPTS_HPP
#define RAWSTOR_MDS_OPTS_HPP

namespace rawstor {
namespace mdsserver {

struct Opts {
    // Each probe needs up to 8 queue entries; 1024 keeps the monitor's
    // io_uring depth (16384) below the kernel's 32768-entry limit.
    static constexpr unsigned int max_info_concurrency = 1024;

    unsigned int info_interval = 60000; // milliseconds
    unsigned int info_concurrency = 128;

    static Opts from_env();
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_OPTS_HPP
