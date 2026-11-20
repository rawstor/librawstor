#ifndef RAWSTD_UUID_H
#define RAWSTD_UUID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct RawstdUUID {
    uint8_t bytes[16];
};

typedef char RawstdUUIDString[37];

/*
 * Short form: the 16 bytes in unpadded base64url (RFC 4648 section 5), 22
 * characters instead of the 36 of RawstdUUIDString. Its alphabet
 * (A-Z a-z 0-9 - _) is legal in file, LVM and ZFS names, so it fits where
 * the full string would overflow a name length limit.
 */
#define RAWSTD_UUID_SHORT_STRING_LEN 22

typedef char RawstdUUIDShortString[RAWSTD_UUID_SHORT_STRING_LEN + 1];

int rawstd_uuid7_init(struct RawstdUUID* uuid);

int rawstd_uuid_from_string(struct RawstdUUID* uuid, const char* s);

void rawstd_uuid_to_string(const struct RawstdUUID* uuid, RawstdUUIDString* s);

void rawstd_uuid_to_short_string(
    const struct RawstdUUID* uuid, RawstdUUIDShortString* s
);

/*
 * Parses exactly RAWSTD_UUID_SHORT_STRING_LEN characters, -EINVAL for
 * anything else, including a non-canonical one (nonzero trailing bits), so
 * every UUID has exactly one short string.
 */
int rawstd_uuid_from_short_string(struct RawstdUUID* uuid, const char* s);

int rawstd_uuid_cmp(const struct RawstdUUID* lhs, const struct RawstdUUID* rhs);

/*
 * True for the all-zero UUID -- never a value rawstd_uuid7_init() itself
 * produces (version/variant are always stamped nonzero), so callers can
 * safely reserve it as a "no id bound" sentinel without risking a
 * collision with a real, generated one.
 */
int rawstd_uuid_is_nil(const struct RawstdUUID* uuid);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_UUID_H
