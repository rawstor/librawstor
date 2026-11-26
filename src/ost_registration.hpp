#ifndef RAWSTOR_OST_REGISTRATION_HPP
#define RAWSTOR_OST_REGISTRATION_HPP

#include <rawstd/uuid.h>

#include <rawstor/location.h>

#include <string>

#include <cstdint>

namespace rawstor {

/*
 * The members an OST holds, summed up so that the MDS can tell whether its map
 * agrees without listing them (docs/mds.md, "Member digest"): how many there
 * are and the sum, modulo 2^64, of a hash of each one's object id and chunk
 * offset. The sum does not depend on the order they are added in.
 */
struct MemberDigest {
    uint64_t count = 0;
    uint64_t hash = 0;

    void add(const RawstdUUID& id, uint64_t offset);

    bool operator==(const MemberDigest&) const = default;
};

/*
 * What an OST tells the MDS of its cluster about itself (OST_REGISTER,
 * <rawstor/protocol.h>). `domain` is its failure domain path,
 * "[[[dc/]row/]rack/]server". A `sampled` registration carries the OST's
 * latest `info` and `members`; one that is not leaves the MDS's sample as it
 * is. A `leaving` one takes the OST out of placement until it registers again.
 */
struct OstRegistration {
    RawstdUUID id{};
    std::string location;
    uint64_t weight = 0;
    std::string domain;
    bool sampled = false;
    RawstorLocationInfo info{};
    MemberDigest members;
    bool leaving = false;
};

/* What the MDS asks of the OST in return, in milliseconds. */
struct OstRegistered {
    unsigned int heartbeat_interval = 0;
    unsigned int info_interval = 0;
    unsigned int info_refresh_delay = 0;
};

/*
 * Splits a root-first failure domain path, "[[[dc/]row/]rack/]server", into
 * the dc, row, rack and server slots of `out`. Only the server is required;
 * the path may start at any level, and a level left out stays empty, so that
 * every OST that leaves it out shares that one implicit domain. EINVAL for an
 * empty component or more than four.
 */
void split_domain(const std::string& domain, std::string (&out)[4]);

} // namespace rawstor

#endif // RAWSTOR_OST_REGISTRATION_HPP
