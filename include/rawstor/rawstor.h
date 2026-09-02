/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_RAWSTOR_H
#define RAWSTOR_RAWSTOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define RAWSTOR_NOEXCEPT noexcept
#else
#define RAWSTOR_NOEXCEPT
#endif

struct RawstorOpts {
    unsigned int io_attempts;
    unsigned int sessions;
    unsigned int so_sndtimeo;
    unsigned int so_rcvtimeo;
    unsigned int tcp_user_timeout;
    unsigned int list_limit;
    unsigned int write_throttle_limit;
    unsigned int write_backlog_capacity;
    unsigned int io_retry_backoff_base;
    unsigned int io_retry_backoff_max;
    unsigned int io_retry_backoff_jitter;
    /**
     * How often, in milliseconds, an open mirrored object probes its
     * unreachable arms for reconnection (and resyncs them on success).
     */
    unsigned int mirror_probe_interval;
};

typedef struct {
    uint8_t bytes[16];
} RawstorPaginationToken;

/**
 * @brief Check whether a pagination token is empty.
 *
 * This function tests if the given @p token represents an empty state,
 * indicating that no more objects are available in the listing operation.
 * An empty token is typically returned by @ref rawstor_location_list when
 * the end of the object list has been reached.
 *
 * The token is considered empty if all its bytes are zero. Callers can
 * zero‑initialize a token before the first invocation of
 * @ref rawstor_location_list and then use this function in a loop to
 * determine when to stop pagination.
 *
 * @param token     Pointer to a RawstorPaginationToken structure to check.
 *                  Must not be NULL.
 *
 * @return Non‑zero (true) if the token is empty (all bytes zero), zero
 *         (false) otherwise.
 *
 * @warning Passing NULL results in undefined behaviour.
 *
 * @see rawstor_location_list
 */
int rawstor_pagination_token_empty(
    const RawstorPaginationToken* token
) RAWSTOR_NOEXCEPT;

int rawstor_initialize(const struct RawstorOpts* opts) RAWSTOR_NOEXCEPT;

void rawstor_terminate(void) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_RAWSTOR_H
