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
};

int rawstor_initialize(const struct RawstorOpts* opts) RAWSTOR_NOEXCEPT;

void rawstor_terminate(void) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_RAWSTOR_H
