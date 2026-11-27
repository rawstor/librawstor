#ifndef RAWSTOR_MDS_OPTS_HPP
#define RAWSTOR_MDS_OPTS_HPP

namespace rawstor {
namespace mdsserver {

/*
 * What the MDS asks of the OSTs that register with it (docs/mds.md, "OST
 * registration"), in milliseconds.
 */
struct Opts {
    // Between two registrations of an OST; one that misses three is
    // unavailable.
    unsigned int heartbeat_interval = 10000;
    // How long an OST's space and member sample is good for.
    unsigned int info_interval = 300000;
    // How long after an OST creates or removes a member it samples again,
    // so that a client's burst of them is sampled once, after the last.
    unsigned int info_refresh_delay = 5000;

    static Opts from_env();
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_OPTS_HPP
