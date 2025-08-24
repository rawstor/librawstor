#include "rawstorstd/uuid.h"
#include "uuid_internals.h"

#include "unittest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>


static int test_timestamp() {
    struct RawstorUUID uuid;
    assertTrue(rawstor_uuid7_set_timestamp(&uuid, 100) == 0);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == 100);
    assertTrue(rawstor_uuid7_set_timestamp(&uuid, (1ull << 48) - 1) == 0);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == (1ull << 48) - 1);
    assertTrue(rawstor_uuid7_set_timestamp(&uuid, (1ull << 48)) == -ERANGE);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == (1ull << 48) - 1);
    return 0;
}


static int test_counter() {
    struct RawstorUUID uuid;
    assertTrue(rawstor_uuid7_set_counter(&uuid, 100) == 0);
    assertTrue(rawstor_uuid7_get_counter(&uuid) == 100);
    assertTrue(rawstor_uuid7_set_counter(&uuid, (1ull << 42) - 1) == 0);
    assertTrue(rawstor_uuid7_get_counter(&uuid) == (1ull << 42) - 1);
    assertTrue(rawstor_uuid7_set_counter(&uuid, (1ull << 42)) == -ERANGE);
    assertTrue(rawstor_uuid7_get_counter(&uuid) == (1ull << 42) - 1);
    return 0;
}


static int test_version() {
    for (int version = 0; version < 16; ++version) {
        struct RawstorUUID uuid;
        rawstor_uuid_set_version(&uuid, version);
        assertTrue(rawstor_uuid_get_version(&uuid) == version);
    }
    return 0;
}


static int test_variant() {
    for (int variant = 0; variant < 4; ++variant) {
        struct RawstorUUID uuid;
        rawstor_uuid_set_variant(&uuid, variant);
        assertTrue(rawstor_uuid_get_variant(&uuid) == variant);
    }
    return 0;
}


static int test_all_at_once() {
    RawstorUUIDString s;
    struct RawstorUUID uuid = {0};
    rawstor_uuid_set_version(&uuid, 7);
    rawstor_uuid_set_variant(&uuid, 2);
    rawstor_uuid7_set_counter(&uuid, (1ull << 42) - 1);
    rawstor_uuid7_set_timestamp(&uuid, (1ull << 48) - 1);

    assertTrue(rawstor_uuid_get_version(&uuid) == 7);
    assertTrue(rawstor_uuid_get_variant(&uuid) == 2);
    assertTrue(rawstor_uuid7_get_counter(&uuid) == (1ull << 42) - 1);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == (1ull << 48) - 1);

    rawstor_uuid_to_string(&uuid, &s);
    assertTrue(strcmp(s, "ffffffff-ffff-7fff-bfff-ffff00000000") == 0);
    return 0;
}


static int test_init() {
    struct RawstorUUID uuid;
    assertTrue(rawstor_uuid7_init(&uuid) == 0);

    assertTrue(rawstor_uuid_get_version(&uuid) == 7);
    assertTrue(rawstor_uuid_get_variant(&uuid) == 2);

    return 0;
}


static int test_from_string() {
    struct RawstorUUID uuid;
    assertTrue(rawstor_uuid_from_string(
        &uuid, "0195e6ef-3ba8-741d-af22-e02bf9c800ec") == 0);

    assertTrue(rawstor_uuid_get_version(&uuid) == 7);
    assertTrue(rawstor_uuid_get_variant(&uuid) == 2);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == 1743336192936ul);
    assertTrue(rawstor_uuid7_get_counter(&uuid) == 1131440955435ul);

    return 0;
}


static int test_from_string_errors() {
    struct RawstorUUID uuid;
    assertTrue(rawstor_uuid_from_string(
        &uuid, "0195e6ef-3ba8-741d-af22-e02bf9c800ec") == 0);

    assertTrue(rawstor_uuid_from_string(
        &uuid, "0195E6EF-3BA8-741D-AF22-E02BF9C800EC") == 0);

    assertTrue(rawstor_uuid_from_string(
        &uuid, "0195e6ef-3ba8-741d-af22-e02bf9c800ecX") == 0);

    assertTrue(rawstor_uuid_from_string(
        &uuid, "0195e6efX3ba8-741d-af22-e02bf9c800ec") == -EINVAL);

    assertTrue(rawstor_uuid_from_string(
        &uuid, "0195e6ef-3ba8-741d-af22-e02bf9c800e") == -EINVAL);

    assertTrue(rawstor_uuid_from_string(
        &uuid, "X195e6ef-3ba8-741d-af22-e02bf9c800ec") == -EINVAL);

    return 0;
}


static int test_from_string_debug() {
    struct RawstorUUID uuid;
    assertTrue(rawstor_uuid_from_string(&uuid, "a") == 0);

    RawstorUUIDString s;
    rawstor_uuid_to_string(&uuid, &s);
    assertTrue(strcmp(s, "00000000-0000-7000-8000-000a00000000") == 0);

    assertTrue(rawstor_uuid_from_string(&uuid, "x") == -EINVAL);
    return 0;
}


int main() {
    int rval = 0;
    rval += test_timestamp();
    rval += test_counter();
    rval += test_version();
    rval += test_variant();
    rval += test_all_at_once();
    rval += test_init();
    rval += test_from_string();
    rval += test_from_string_errors();
    rval += test_from_string_debug();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
