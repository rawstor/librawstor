#ifndef RAWSTOR_MDS_OPTS_HPP
#define RAWSTOR_MDS_OPTS_HPP

namespace rawstor {
namespace mdsserver {

struct Opts {
    unsigned int info_interval = 60000; // milliseconds
    unsigned int info_concurrency = 128;

    static Opts from_env();
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_OPTS_HPP
