#include "uuid.h"
#include "uuid_internals.h"

#include <sys/random.h>

#include <errno.h>
#include <stdint.h>
#include <time.h>


static inline uint64_t uuid7_get_timestamp(const RawstorUUID *uuid) {
    uint64_t ts = 0;
    ts = uuid->bytes[0];
    ts = (ts << 8) | uuid->bytes[1];
    ts = (ts << 8) | uuid->bytes[2];
    ts = (ts << 8) | uuid->bytes[3];
    ts = (ts << 8) | uuid->bytes[4];
    ts = (ts << 8) | uuid->bytes[5];
    return ts;
}


static inline int uuid7_set_timestamp(RawstorUUID *uuid, uint64_t ts) {
    static const uint64_t MAX_TIMESTAMP = (1ull << 48) - 1;

    if (ts > MAX_TIMESTAMP) {
        errno = ERANGE;
        return -errno;
    }

    uuid->bytes[0] = ts >> 40;
    uuid->bytes[1] = ts >> 32;
    uuid->bytes[2] = ts >> 24;
    uuid->bytes[3] = ts >> 16;
    uuid->bytes[4] = ts >> 8;
    uuid->bytes[5] = ts;

    return 0;
}


static inline uint64_t uuid7_get_counter(const RawstorUUID *uuid) {
    uint64_t counter = uuid->bytes[6] & 0b00001111;
    counter = (counter << 8) | uuid->bytes[7];
    counter = (counter << 6) | (uuid->bytes[8] & 0b00111111);
    counter = (counter << 8) | uuid->bytes[9];
    counter = (counter << 8) | uuid->bytes[10];
    counter = (counter << 8) | uuid->bytes[11];
    return counter;
}


static inline int uuid7_set_counter(RawstorUUID *uuid, uint64_t counter) {
    static const uint64_t MAX_COUNTER = (1ull << 42) - 1;

    if (counter > MAX_COUNTER) {
        errno = ERANGE;
        return -errno;
    }

    uuid->bytes[6] = (uuid->bytes[6] & 0b11110000) | counter >> 38;
    uuid->bytes[7] = counter >> 30;
    uuid->bytes[8] =
        (uuid->bytes[8] & 0b11000000)
        | ((counter >> 24) & 0b00111111);
    uuid->bytes[9] = counter >> 16;
    uuid->bytes[10] = counter >> 8;
    uuid->bytes[11] = counter;
    return 0;
}


static inline uint8_t uuid_get_version(RawstorUUID *uuid) {
    return uuid->bytes[6] >> 4;
}


static inline void uuid_set_version(RawstorUUID *uuid, uint8_t version) {
    uuid->bytes[6] = (version << 4) | (uuid->bytes[6] & 0b00001111);
}


static inline uint8_t uuid_get_variant(RawstorUUID *uuid) {
    return uuid->bytes[8] >> 6;
}


static inline void uuid_set_variant(RawstorUUID *uuid, uint8_t variant) {
    uuid->bytes[8] = (variant << 6) | (uuid->bytes[8] & 0b00111111);
}


static inline int uuid_add_entropy(RawstorUUID *uuid, unsigned int size) {
    if (getentropy(&uuid->bytes[16 - size], size)) {
        return -errno;
    }
    return 0;
}


uint64_t rawstor_uuid7_get_timestamp(const RawstorUUID *uuid) {
    return uuid7_get_timestamp(uuid);
}


int rawstor_uuid7_set_timestamp(RawstorUUID *uuid, uint64_t ts) {
    return uuid7_set_timestamp(uuid, ts);
}


uint64_t rawstor_uuid7_get_counter(const RawstorUUID *uuid) {
    return uuid7_get_counter(uuid);
}


int rawstor_uuid7_set_counter(RawstorUUID *uuid, uint64_t counter) {
    return uuid7_set_counter(uuid, counter);
}

uint8_t rawstor_uuid_get_version(RawstorUUID *uuid) {
    return uuid_get_version(uuid);
}


void rawstor_uuid_set_version(RawstorUUID *uuid, uint8_t version) {
    return uuid_set_version(uuid, version);
}


uint8_t rawstor_uuid_get_variant(RawstorUUID *uuid) {
    return uuid_get_variant(uuid);
}


void rawstor_uuid_set_variant(RawstorUUID *uuid, uint8_t variant) {
    uuid_set_variant(uuid, variant);
}


int rawstor_uuid7_init(RawstorUUID *uuid) {
    static RawstorUUID prev_uuid = {0};

    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp)) {
        return -errno;
    }
    uint64_t ts = 1000ull * tp.tv_sec + tp.tv_nsec / 1000000l;

    uint64_t prev_ts = uuid7_get_timestamp(&prev_uuid);

    int entropy_size = 10;
    if (ts >= prev_ts - 10000 && ts <= prev_ts) {
        uint64_t counter = uuid7_get_counter(&prev_uuid);
        if (uuid7_set_counter(uuid, counter + 1) == 0) {
            entropy_size = 4;
        } else {
            if (errno != ERANGE) {
                return -errno;
            }
            ++ts;
        }
    }

    if (uuid_add_entropy(uuid, entropy_size)) {
        return -errno;
    }

    if (uuid7_set_timestamp(uuid, ts)) {
        return -errno;
    }

    uuid_set_version(uuid, 7);
    uuid_set_variant(uuid, 2);

    prev_uuid = *uuid;

    return 0;
}


void rawstor_uuid_to_string(const RawstorUUID *uuid, RawstorUUIDString *s) {
    static const char alphabet[] = "0123456789abcdef";
    char *p = *s;
    for (int i = 0; i < 16; ++i) {
      uint_fast8_t e = uuid->bytes[i];
      *p++ = alphabet[e >> 4];
      *p++ = alphabet[e & 0b00001111];
      if (i == 3 || i == 5 || i == 7 || i == 9) {
        *p++ = '-';
      }
    }
    *p = '\0';
}


int rawstor_uuid_from_string(const char *s, RawstorUUID *uuid) {
    /**
     * TODO: Delete this logic before first release.
     * This is for debug purposes only.
     */
    if (s[1] == 0) {
        char c = *s;
        uint8_t x =
            (c >= '0' && c <= '9') ? c - '0'
            : (c >= 'a' && c <= 'f') ? 10 + c - 'a'
            : (c >= 'A' && c <= 'F') ? 10 + c - 'A'
            : 0xff;

        if (x == 0xff) {
            errno = EINVAL;
            return -errno;
        }

        RawstorUUID ret = {0};
        uuid_set_version(&ret, 7);
        uuid_set_variant(&ret, 2);
        uuid7_set_counter(&ret, x);
        *uuid = ret;

        return 0;
    }

    const char *p = s;
    for (int i = 0; i < 32; i++) {
        char c = *p++;

        uint8_t x =
            (c >= '0' && c <= '9') ? c - '0'
            : (c >= 'a' && c <= 'f') ? 10 + c - 'a'
            : (c >= 'A' && c <= 'F') ? 10 + c - 'A'
            : 0xff;

        if (x == 0xff) {
            errno = EINVAL;
            return -errno;
        }

        if ((i & 1) == 0) {
            uuid->bytes[i >> 1] = x << 4;
        } else {
            uuid->bytes[i >> 1] |= x;
        }

        if ((i == 7 || i == 11 || i == 15 || i == 19) && (*p++ != '-')) {
            errno = EINVAL;
            return -errno;
        }
    }
    return 0;
}
