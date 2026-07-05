/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_RAWSTOR_H
#define RAWSTOR_RAWSTOR_H

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
    /**
     * How long to wait, in milliseconds, for a block device node to appear
     * after a backend provisioning command (lvcreate, zfs create) succeeds.
     */
    unsigned int wait_device_timeout;
    /**
     * How often, in milliseconds, an open mirrored object probes its
     * unreachable arms for reconnection (and resyncs them on success).
     */
    unsigned int mirror_probe_interval;
};

int rawstor_initialize(const struct RawstorOpts* opts) RAWSTOR_NOEXCEPT;

void rawstor_terminate(void) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_RAWSTOR_H
