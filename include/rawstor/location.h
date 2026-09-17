/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_LOCATION_H
#define RAWSTOR_LOCATION_H

#include <rawstor/list.h>
#include <rawstor/rawstor.h>
#include <rawstor/target.h>

#include <stddef.h>
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
 * @brief Asynchronously retrieve aggregate space usage for a location.
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
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue     Queue used to drive the asynchronous lookup.
 * @param location  Location string, e.g.:
 *                  - "ost://127.0.0.1:9090"
 *                  - "file:///var/rawstor"
 *                  - "ost://host1:9090,ost://host2:9090"        (mirroring)
 *                  - "file:///data,ost://host:9090"              (locality)
 * @param info      Out-parameter written exactly once, immediately before
 *                  @p cb is invoked: the location's space information on
 *                  success. Left untouched on error, and never written at
 *                  all if the lookup is never queued (see the return value
 *                  below).
 * @param cb        Callback invoked on completion.
 *                  - @p result is zero on success, or a negative errno on
 *                    failure (@c -EINVAL for invalid location syntax --
 *                    e.g. malformed URI, empty list, duplicate URIs --,
 *                    @c -ENOENT if the location does not exist or is
 *                    unreachable, @c -EIO for a network/filesystem error,
 *                    @c -EACCES if permission was denied).
 *                  - @p data is the same pointer passed as @p data below.
 *                  - Return zero on success. A negative errno value signals
 *                    an error back into the I/O completion machinery.
 * @param data      User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the lookup was successfully queued; negative errno on
 *         immediate failure (in which case neither @p info nor @p cb is
 *         ever touched). The actual result is delivered via @p info/@p cb.
 *
 * @see RawstorLocationInfo
 * @see Location and Target documentation in Rawstor user guide:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_location_info(
    RawIOQueue* queue, const char* location, struct RawstorLocationInfo* info,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously list objects stored at the given location.
 *
 * This function retrieves a list of object identifiers (full target strings)
 * stored at the specified @p location. The location must be a comma separated
 * list of valid backend URI as described in the Locations and Targets
 * documentation. The function supports pagination via the @p token parameter,
 * allowing the caller to iterate over large sets of objects.
 *
 * The objects are returned in lexicographic order by their UUID. The
 * @p limit parameter restricts the maximum number of objects returned in a
 * single call. If @p limit is 0, the backend chooses an appropriate number
 * of objects to return. The backend may enforce its own maximum limit
 * (e.g., via the @c RAWSTOR_OPTS_LIST_LIMIT environment variable on the
 * server side) that caps the actual number of strings returned, regardless
 * of the @p limit value specified by the caller. If the number of objects
 * available exceeds the effective limit (either specified by the caller or
 * chosen by the backend), the function fills the @p token with an opaque
 * pagination token that must be passed in the subsequent call to continue
 * iteration. When the end of the list is reached, the token is set to an
 * empty state (as determined by @ref rawstor_pagination_token_empty).
 *
 * The caller is responsible for freeing the returned string list using
 * @ref rawstor_string_list_delete. The pagination token is a plain structure
 * of fixed size (16 bytes) and does not require explicit deallocation;
 * it should be zero‑initialized before the first call.
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue     Queue used to drive the asynchronous listing.
 * @param location  Location string specifying the backend and endpoint
 *                  (e.g., "ost://host:port" or "file:///path"). Must not be
 *                  NULL and must be a valid location as per the library's
 *                  format. The behaviour is identical to the @p location
 *                  parameter of @ref rawstor_location_create.
 * @param limit     Maximum number of objects to return in this call. If 0, the
 *                  backend chooses the number of objects to return. The actual
 *                  number of objects returned may also be limited by the
 *                  backend's internal configuration (e.g., the
 *                  @c RAWSTOR_OPTS_LIST_LIMIT environment variable on the
 *                  server side).
 * @param targets   Out-parameter written exactly once, immediately before
 *                  @p cb is invoked: on success, a pointer to a newly
 *                  allocated @ref RawstorStringList. The list contains full
 *                  target strings (e.g., "ost://host:port/<uuid>") for each
 *                  object. The caller must destroy the list using
 *                  @ref rawstor_string_list_delete when it is no longer
 *                  needed. Left untouched on error, and never written at all
 *                  if the listing is never queued (see the return value
 *                  below).
 * @param token     Input/Output parameter for pagination. On the first call,
 *                  the caller must zero‑initialize the structure (e.g.,
 *                  `RawstorPaginationToken token = {};`). On success, the
 *                  function fills the token with an opaque value (before
 *                  @p cb is invoked) if more objects are available, or sets
 *                  it to an empty state otherwise (checkable via
 *                  @ref rawstor_pagination_token_empty). The caller must
 *                  pass the same token structure (with the value returned
 *                  from the previous call) in subsequent calls to retrieve
 *                  the next page. The token is opaque and must not be
 *                  modified by the caller. Must stay valid until @p cb runs.
 * @param cb        Callback invoked on completion.
 *                  - @p result is zero on success (the @p targets list and
 *                    @p token are valid), or a negative errno on failure
 *                    (@c -EINVAL for invalid @p location, @c -ENOMEM if
 *                    allocating the list failed, @c -ENOENT if @p location
 *                    does not exist or is unreachable, @c -EIO for a
 *                    network/filesystem error, @c -EACCES if permission was
 *                    denied). The function may report a partial listing even
 *                    on failure (e.g. if a backend becomes unavailable
 *                    mid‑iteration); callers should not rely on @p targets/
 *                    @p token when @p result is negative.
 *                  - @p data is the same pointer passed as @p data below.
 *                  - Return zero on success. A negative errno value signals
 *                    an error back into the I/O completion machinery.
 * @param data      User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the listing was successfully queued; negative errno on
 *         immediate failure (in which case neither @p targets, @p token, nor
 *         @p cb is ever touched). The actual result is delivered via
 *         @p targets/@p token/@p cb.
 *
 * @note If an invalid or corrupted token is passed (e.g., from a previous
 *       session or after modifications to the storage), the behaviour is
 *       undefined; the function may return incomplete or inconsistent results.
 *
 * @note Objects inserted into the already‑retrieved portion of the list
 *       between calls will not be visible in subsequent iterations; the
 *       token‑based pagination ensures consistency within the current
 *       iteration session.
 *
 * @see rawstor_string_list_delete
 * @see rawstor_pagination_token_empty
 * @see rawstor_location_create
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_location_list(
    RawIOQueue* queue, const char* location, unsigned int limit,
    RawstorStringList** targets, RawstorPaginationToken* token,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously create an empty object at the specified location
 *        with optional UUID, and return the constructed target string.
 *
 * This function creates a new object at the given @p location. If @p uuid is
 * NULL, the library automatically generates a unique UUID for the object;
 * otherwise, the provided UUID is used. The object metadata (size, etc.) is
 * provided via the @p spec structure.
 *
 * The function constructs the full target identifier from @p location and
 * @p uuid according to the library's target format (e.g.,
 * "ost://host:port/<uuid>") -- this requires no I/O, so it happens
 * synchronously, before this call even returns. It then attempts to copy the
 * resulting string into the caller‑supplied buffer @p target of size @p size
 * bytes, **including** the terminating null character.
 *
 * The result delivered via @p cb follows the semantics of `snprintf()`:
 * - If the entire target string fits in the buffer, the full string
 *   (including the null terminator) is written to @p target synchronously
 *   (before this call returns), and the object creation itself is queued;
 *   @p cb eventually reports the number of characters that would have been
 *   written (excluding the terminating null) -- always non-negative, and
 *   less than @p size -- once the object is actually created, or a negative
 *   errno if that fails.
 * - If the buffer is too small to hold the complete target string, the
 *   object is **not** created, no data is written to @p target (or the
 *   buffer may be left unchanged), and -- since nothing needed to be queued
 *   -- @p cb is invoked synchronously, from within this same call, with the
 *   number of characters that would have been required (excluding the null
 *   terminator; always non-negative, and greater than or equal to @p size).
 *   This is exactly the same behaviour as `snprintf()` when the buffer is
 *   too small, except that here the object creation is aborted and the
 *   value is reported through @p cb rather than this call's own return
 *   value.
 * - On other errors (e.g., invalid parameters, memory allocation failure, I/O
 *   problems), @p cb receives a negative errno.
 *
 * @param queue     Queue used to drive the asynchronous create.
 * @param location  Location string specifying the backend and endpoint
 *                  (e.g., "ost://host:port"). Must not be NULL and must be a
 *                  valid location as per the library's format.
 * @param uuid      UUID string for the object. If NULL, a UUID is automatically
 *                  generated. If not NULL, it must be a valid UUID string.
 *                  Only read while this call is being queued -- need not
 *                  stay valid until @p cb runs.
 * @param spec      Pointer to a RawstorObjectSpec structure containing the
 *                  desired object metadata (e.g., size in bytes). The size
 *                  field must be set to the expected size of the object.
 *                  Only read while this call is being queued -- need not
 *                  stay valid until @p cb runs.
 * @param target    Output buffer that will receive the full target string
 *                  (e.g., "ost://host:port/<uuid>"). Must not be NULL. Filled
 *                  synchronously (before this call returns) whenever the
 *                  string fits, whether or not the create itself later
 *                  succeeds.
 * @param size      Size of the @p target buffer in bytes, including space for
 *                  the terminating null character. The buffer must be large
 *                  enough to hold the complete string; if not, the object is
 *                  not created and the required length is reported via
 *                  @p cb.
 * @param cb        Callback invoked on completion (synchronously, from
 *                  within this same call, when @p target was too small --
 *                  see above -- or otherwise once the actual create
 *                  completes).
 *                  - @p result is the target string's length (see above) on
 *                    success or when @p target was too small, or a negative
 *                    errno on failure (e.g. @c -EINVAL for invalid
 *                    parameters, @c -ENOMEM, @c -EIO, etc;
 *                    implementation‑defined beyond that).
 *                  - @p data is the same pointer passed as @p data below.
 *                  - Return zero on success. A negative errno value signals
 *                    an error back into the I/O completion machinery.
 * @param data      User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if @p cb has been (or will be) invoked -- whether synchronously
 *         (buffer too small) or once the create completes; negative errno on
 *         immediate failure (e.g. invalid @p uuid, malformed @p location),
 *         in which case @p cb is never invoked.
 *
 * @see RawstorObjectSpec
 * @see rawstor_target_create
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_location_create(
    RawIOQueue* queue, const char* location, const char* uuid,
    const struct RawstorObjectSpec* spec, char* target, size_t size,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_LOCATION_H
