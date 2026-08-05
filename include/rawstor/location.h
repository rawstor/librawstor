/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_LOCATION_H
#define RAWSTOR_LOCATION_H

#include <rawstor/rawstor.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Location capacity/usage information.
 *
 * Contains aggregate space accounting for a location, as returned by
 * rawstor_location_info().
 */
struct RawstorLocationInfo {
    uint64_t used;  /**< Space occupied by rawstor objects, in bytes. */
    uint64_t total; /**< Total capacity of the backend, in bytes. */
};

/**
 * @brief Retrieve aggregate space usage for a location.
 *
 * Given a location string (as defined in the Rawstor location/target
 * syntax), this function fills a RawstorLocationInfo structure with
 * space-accounting information about the backend(s) the location refers to.
 *
 * The location may be a single backend URI or a comma-separated list of
 * backend URIs (mirroring / data locality). When multiple backends are
 * given, each is queried independently and the results are combined as
 * follows:
 * - @c total is the minimum of the per-backend totals (the smallest backend
 *   caps how much the whole location can actually hold).
 * - @c used is the maximum of the per-backend used values (mirrors are
 *   expected to hold the same data, but a mirror that is behind on writes
 *   would under-report; taking the maximum avoids that undercount).
 *
 * @param location  Location string, e.g.:
 *                  - "ost://127.0.0.1:9090"
 *                  - "file:///var/rawstor"
 *                  - "ost://host1:9090,ost://host2:9090"        (mirroring)
 *                  - "file:///data,ost://host:9090"              (locality)
 * @param info      Pointer to a RawstorLocationInfo structure that will be
 *                  filled with the location's space information on success.
 *
 * @return 0 on success, negative errno on error.
 * @retval 0        Location info successfully retrieved.
 * @retval -EINVAL  Invalid location syntax (e.g., malformed URI, empty list,
 *                  duplicate URIs).
 * @retval -ENOENT  Location does not exist or is unreachable.
 * @retval -EIO     I/O error (network or filesystem).
 * @retval -EACCES  Permission denied.
 *
 * @see RawstorLocationInfo
 * @see Location and Target documentation in Rawstor user guide:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_location_info(
    const char* location, struct RawstorLocationInfo* info
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_LOCATION_H
