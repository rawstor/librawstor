#include "uuid.h"
#include "uuid_internals.h"

#include "utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>


static int test_timestamp() {
    rawstor_uuid uuid;
    assertTrue(rawstor_uuid7_set_timestamp(&uuid, 100) == 0);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == 100);
    assertTrue(rawstor_uuid7_set_timestamp(&uuid, (1ull << 48) - 1) == 0);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == (1ull << 48) - 1);
    assertTrue(rawstor_uuid7_set_timestamp(&uuid, (1ull << 48)) == -ERANGE);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == (1ull << 48) - 1);
    return 0;
}


static int test_counter() {
    rawstor_uuid uuid;
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
        rawstor_uuid uuid;
        rawstor_uuid_set_version(&uuid, version);
        assertTrue(rawstor_uuid_get_version(&uuid) == version);
    }
    return 0;
}


static int test_variant() {
    for (int variant = 0; variant < 4; ++variant) {
        rawstor_uuid uuid;
        rawstor_uuid_set_variant(&uuid, variant);
        assertTrue(rawstor_uuid_get_variant(&uuid) == variant);
    }
    return 0;
}


static int test_all_at_once() {
    rawstor_uuid_string s;
    rawstor_uuid uuid = {0};
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
    rawstor_uuid uuid;
    assertTrue(rawstor_uuid7_init(&uuid) == 0);

    assertTrue(rawstor_uuid_get_version(&uuid) == 7);
    assertTrue(rawstor_uuid_get_variant(&uuid) == 2);

    return 0;
}


static int test_from_string() {
    rawstor_uuid uuid;
    assertTrue(rawstor_uuid_from_string(
        "0195e6ef-3ba8-741d-af22-e02bf9c800ec", &uuid) == 0);

    assertTrue(rawstor_uuid_get_version(&uuid) == 7);
    assertTrue(rawstor_uuid_get_variant(&uuid) == 2);
    assertTrue(rawstor_uuid7_get_timestamp(&uuid) == 1743336192936ul);
    assertTrue(rawstor_uuid7_get_counter(&uuid) == 1131440955435ul);

    return 0;
}


static int test_from_string_errors() {
    rawstor_uuid uuid;
    assertTrue(rawstor_uuid_from_string(
        "0195e6ef-3ba8-741d-af22-e02bf9c800ec", &uuid) == 0);

    assertTrue(rawstor_uuid_from_string(
        "0195E6EF-3BA8-741D-AF22-E02BF9C800EC", &uuid) == 0);

    assertTrue(rawstor_uuid_from_string(
        "0195e6ef-3ba8-741d-af22-e02bf9c800ecX", &uuid) == 0);

    assertTrue(rawstor_uuid_from_string(
        "0195e6efX3ba8-741d-af22-e02bf9c800ec", &uuid) == -EINVAL);

    assertTrue(rawstor_uuid_from_string(
        "0195e6ef-3ba8-741d-af22-e02bf9c800e", &uuid) == -EINVAL);

    assertTrue(rawstor_uuid_from_string(
        "X195e6ef-3ba8-741d-af22-e02bf9c800ec", &uuid) == -EINVAL);

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
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
