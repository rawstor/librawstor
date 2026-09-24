#include "resolve.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

/* Same buffer-capacity convention as cli/show.c's own MAX_MIRRORS -- one
 * chunk's own mirror count, not the object's own chunk count. */
enum { MAX_MIRRORS = 256 };

/* /dev/urandom rather than arc4random() -- the latter isn't declared
 * until glibc 2.36, older than one of this project's own CI targets
 * (AlmaLinux 9, glibc 2.34), and isn't POSIX either; /dev/urandom exists
 * on both Linux and macOS with no feature-test-macro or glibc-version
 * concerns. Falls back to a PRNG seeded from time+pid if the device
 * can't be read (e.g. a chroot without /dev) -- fine here, since a
 * sync_id only needs to not collide in practice, not be
 * cryptographically unpredictable. Never returns 0 -- that's the
 * "legacy, never synced" sentinel (docs/mirroring.md), not a valid
 * sync_id for an object resolve just declared authoritative. */
static uint64_t random_sync_id(void) {
    uint64_t id = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, &id, sizeof(id));
        close(fd);
        if (n != (ssize_t)sizeof(id)) {
            id = 0;
        }
    }
    while (id == 0) {
        static int seeded = 0;
        if (!seeded) {
            srandom((unsigned int)time(NULL) ^ (unsigned int)getpid());
            seeded = 1;
        }
        id = ((uint64_t)random() << 32) | (uint64_t)random();
    }
    return id;
}

static int history_contains(const uint64_t* history, size_t n, uint64_t id) {
    for (size_t i = 0; i < n; i++) {
        if (history[i] == id) {
            return 1;
        }
    }
    return 0;
}

static int is_winner(const size_t* winners, size_t num_winners, size_t idx) {
    for (size_t i = 0; i < num_winners; i++) {
        if (winners[i] == idx) {
            return 1;
        }
    }
    return 0;
}

/* The single-URI target string for target's idx-th comma-separated member
 * -- the one remaining bit of parsing resolve still needs, since
 * rawstor_target_set_sync_state() below has to be pointed at exactly one
 * member at a time, not the whole mirror set. Caller frees the result.
 * NULL on OOM or if idx is out of range. */
static char* extract_member(const char* target, size_t idx) {
    char* buf = strdup(target);
    if (buf == NULL) {
        return NULL;
    }

    char* saveptr = NULL;
    char* tok = strtok_r(buf, ",", &saveptr);
    for (size_t i = 0; tok != NULL; i++) {
        if (i == idx) {
            char* member = strdup(tok);
            free(buf);
            return member;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    free(buf);
    return NULL;
}

/* Resolves exactly one chunk: `winners` are positions within that
 * chunk's own mirror set (rawstor_target_meta()'s own per-chunk `result`,
 * not target's own flat comma count); `member_base` is where that
 * chunk's own mirrors start in target's own flat comma-separated list
 * (chunk_index * spec.width -- every chunk created together shares one
 * width, Target::create()'s own validation), so extract_member() below
 * can still reach the right raw URI to hand rawstor_target_set_sync_state()
 * one member at a time. */
static int resolve_chunk(
    const char* target, const size_t* winners, size_t num_winners,
    uint64_t offset, size_t member_base
) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    struct RawstorObjectMeta metas[MAX_MIRRORS];
    int mres = rawstor_target_meta(
        op.queue, target, offset, metas, MAX_MIRRORS, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, mres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_meta() failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }
    if (result > MAX_MIRRORS) {
        fprintf(
            stderr,
            "rawstor resolve: chunk[%llx] has %zd mirrors, more "
            "than this CLI can handle (%d)\n",
            (unsigned long long)offset, result, MAX_MIRRORS
        );
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < num_winners; i++) {
        if (winners[i] >= (size_t)result) {
            fprintf(
                stderr,
                "--winner %zu is out of range (chunk[%llx] has %zd "
                "mirrors)\n",
                winners[i], (unsigned long long)offset, result
            );
            return EX_USAGE;
        }
        if (metas[winners[i]].sync_state.state ==
            RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            fprintf(
                stderr,
                "chunk[%llx]: mirror[%zu] is unreachable; cannot resolve "
                "using it as a winner\n",
                (unsigned long long)offset, winners[i]
            );
            return EXIT_FAILURE;
        }
    }

    /* The new sync_id must dominate every other reachable mirror's own
     * sync_id (docs/mirroring.md's dominance rule, Object::
     * _reconcile_sync_set() in src/object.cpp): its own sync_id_history
     * must contain each of theirs, or the next open still sees disjoint
     * histories and refuses with -ENOTRECOVERABLE again. This includes
     * every OTHER winner's own current sync_id too, in case they were
     * declared jointly authoritative despite having diverged from each
     * other on paper (e.g. a manually-restored backup copied to more than
     * one member) -- only members left out of --winner get resynced. */
    uint64_t history[RAWSTOR_OBJECT_SYNC_ID_HISTORY] = {0};
    size_t history_len = 0;
    uint64_t max_epoch = 0;
    int dropped = 0;
    for (ssize_t i = 0; i < result; i++) {
        const struct RawstorObjectMeta* m = &metas[i];
        if (m->sync_state.state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            continue;
        }
        if (m->sync_state.epoch > max_epoch) {
            max_epoch = m->sync_state.epoch;
        }
        if (is_winner(winners, num_winners, (size_t)i)) {
            continue;
        }
        if (m->sync_state.sync_id == 0 ||
            history_contains(history, history_len, m->sync_state.sync_id)) {
            continue;
        }
        if (history_len < RAWSTOR_OBJECT_SYNC_ID_HISTORY) {
            history[history_len++] = m->sync_state.sync_id;
        } else {
            dropped++;
        }
    }
    if (dropped > 0) {
        fprintf(
            stderr,
            "warning: chunk[%llx]: %d other mirror sync_id(s) didn't fit "
            "in the new sync_id_history (capacity %d); those mirrors "
            "will still resync, just not via a recorded ancestry\n",
            (unsigned long long)offset, dropped, RAWSTOR_OBJECT_SYNC_ID_HISTORY
        );
    }

    struct RawstorObjectSyncState new_state = {
        .epoch = max_epoch + 1,
        .sync_id = random_sync_id(),
        .sync_id_history = {0},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
    };
    memcpy(new_state.sync_id_history, history, sizeof(history));

    /* Every winner gets the exact same new identity, written one at a
     * time (rawstor_target_set_sync_state() only ever points at a single
     * member here, same as the one-winner case) -- as many as already
     * succeeded stay written even if a later one fails, same "partial
     * failure leaves as many copies updated as possible" spirit as
     * Target::set_sync_state()'s own fan-out. */
    for (size_t i = 0; i < num_winners; i++) {
        char* winner_target = extract_member(target, member_base + winners[i]);
        if (winner_target == NULL) {
            fprintf(stderr, "Out of memory\n");
            return EXIT_FAILURE;
        }

        RawstorCliOp set_op;
        res = rawstor_cli_op_init(&set_op);
        if (res < 0) {
            free(winner_target);
            fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
            return rawstd_exitcode_for_errno(-res);
        }
        int sres = rawstor_target_set_sync_state(
            set_op.queue, winner_target, offset, &new_state, rawstor_cli_op_cb,
            &set_op
        );
        ssize_t sresult = rawstor_cli_op_wait(&set_op, sres);
        rawstor_cli_op_destroy(&set_op);
        if (sresult < 0) {
            fprintf(
                stderr,
                "chunk[%llx]: mirror[%zu]: rawstor_target_set_sync_state() "
                "failed: %s\n",
                (unsigned long long)offset, winners[i], strerror((int)-sresult)
            );
            free(winner_target);
            return rawstd_exitcode_for_errno((int)-sresult);
        }

        /* sync_id in hex, epoch in decimal -- same base each one is
         * displayed in everywhere else (rawstor show -v, meta_encode()'s
         * own on-disk encoding). */
        printf(
            "chunk[%llx]: mirror[%zu] (%s) is now authoritative: sync_id "
            "%llx -> %llx, epoch %llu -> %llu\n",
            (unsigned long long)offset, winners[i], winner_target,
            (unsigned long long)metas[winners[i]].sync_state.sync_id,
            (unsigned long long)new_state.sync_id,
            (unsigned long long)metas[winners[i]].sync_state.epoch,
            (unsigned long long)new_state.epoch
        );
        free(winner_target);
    }
    printf(
        "chunk[%llx]: every other reachable mirror will resync on the "
        "next open.\n",
        (unsigned long long)offset
    );

    return EXIT_SUCCESS;
}

int rawstor_cli_resolve(
    const char* target, const size_t* winners, size_t num_winners,
    int has_offset, uint64_t offset
) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    struct RawstorObjectSpec spec;
    int sres =
        rawstor_target_spec(op.queue, target, &spec, rawstor_cli_op_cb, &op);
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_spec() failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    if (has_offset) {
        uint64_t chunk_index =
            spec.chunk_size == 0 ? 0 : offset / spec.chunk_size;
        return resolve_chunk(
            target, winners, num_winners, offset,
            (size_t)chunk_index * spec.width
        );
    }

    uint64_t chunk_count =
        spec.chunk_size == 0
            ? 1
            : (spec.size + spec.chunk_size - 1) / spec.chunk_size;
    for (uint64_t i = 0; i < chunk_count; i++) {
        int ret = resolve_chunk(
            target, winners, num_winners, i * spec.chunk_size,
            (size_t)i * spec.width
        );
        if (ret != EXIT_SUCCESS) {
            return ret;
        }
    }
    return EXIT_SUCCESS;
}
