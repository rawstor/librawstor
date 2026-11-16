/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_PKI_H
#define RAWSTOR_PKI_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Permissions and tenant roles signed into client certificates. */
#define RAWSTOR_PERM_READ 1u
#define RAWSTOR_PERM_WRITE 2u
#define RAWSTOR_PERM_MANAGE 4u
#define RAWSTOR_PERM_ALL                                                       \
    (RAWSTOR_PERM_READ | RAWSTOR_PERM_WRITE | RAWSTOR_PERM_MANAGE)
#define RAWSTOR_ROLE_NONE 0u
#define RAWSTOR_ROLE_READER 1u
#define RAWSTOR_ROLE_WRITER 2u
#define RAWSTOR_ROLE_MANAGER 3u

/**
 * A small certificate authority for installations that have none: a directory
 * with the CA certificate, `ca.crt`, which every process lists as
 * RAWSTOR_TLS_CA, its private key, `ca.key`, readable by its owner only, and
 * the trust domain of the cluster it serves. It issues the certificates a
 * process needs for RAWSTOR_TLS_CERT and RAWSTOR_TLS_KEY, see
 * docs/configuration.md, always in that trust domain.
 *
 * None of these functions needs rawstor_initialize(), so a program can make
 * its certificates before it starts rawstor with them. Every one returns 0, or
 * a negative errno: EEXIST for an init over an existing CA, ENOENT for a CA or
 * a certificate that is not there, EINVAL for a bad trust domain, name or
 * validity or a certificate this CA did not issue. rawstor_pki_error() tells
 * more.
 */

/** The role of the process a certificate is for. */
enum RawstorPkiRole {
    /** A rawstor-ost; `name` is its id, the one in the MDS topology, a UUID. */
    RAWSTOR_PKI_OST,
    /** A rawstor-mds; `name` is its id, a UUID like an OST's. */
    RAWSTOR_PKI_MDS,
    /** An operator or a control plane; `name` is its name. */
    RAWSTOR_PKI_ADMIN,
    /** A tenant's client, such as rawstor-vhost; `tenant` is the tenant's id
     * and `name` the client's name. */
    RAWSTOR_PKI_CLIENT,
};

/** What `identity` of the functions below has to have room for. */
#define RAWSTOR_PKI_IDENTITY_SIZE 2049

/**
 * Creates the directory `dir` (mode 0700) with a new CA for `trust_domain`
 * (lowercase letters, digits, '.', '-' and '_'), valid for `validity` seconds.
 * Refuses to touch a directory that has a CA.
 */
int rawstor_pki_init(
    const char* dir, const char* trust_domain, unsigned long validity
);

/** Explicit object permissions override the role's defaults. Zero denies
 * access. */
#define RAWSTOR_PKI_MAX_OBJECT_PERMISSIONS 128

struct RawstorPkiObjectPermissions {
    char object_id[37];
    unsigned int permissions;
};

struct RawstorPkiPermissions {
    unsigned int role; /* RAWSTOR_ROLE_NONE, READER, WRITER or MANAGER: default
                          permissions */
    size_t count;
    struct RawstorPkiObjectPermissions
        objects[RAWSTOR_PKI_MAX_OBJECT_PERMISSIONS];
};

/**
 * Issues a certificate and a new private key for a process of `role`, valid
 * for `validity` seconds, into `cert_file` and `key_file`, replacing what is
 * there; the key is written with mode 0600. The old pair stays if the new one
 * cannot be written.
 *
 * `tenant` is for a client only and NULL otherwise. `name` may be NULL for an
 * OST or an MDS, which then gets a new id. The SPIFFE ID the certificate names
 * (see docs/security.md) is copied to `identity`, if it is not NULL, with room
 * for RAWSTOR_PKI_IDENTITY_SIZE bytes: `size` is checked before anything is
 * issued. `permissions` applies to tenant clients only; NULL grants no tenant
 * permissions.
 */
int rawstor_pki_issue(
    const char* dir, enum RawstorPkiRole role, const char* tenant,
    const char* name, unsigned long validity, const char* cert_file,
    const char* key_file, char* identity, size_t size,
    const struct RawstorPkiPermissions* permissions
);

/**
 * Issues a new certificate and key for the identity of `cert_file`, which the
 * CA in `dir` must have issued, over the same files. A process picks them up
 * when it is told to reload its certificate. `identity` and `size` are as for
 * rawstor_pki_issue().
 */
int rawstor_pki_renew(
    const char* dir, const char* cert_file, const char* key_file,
    unsigned long validity, char* identity, size_t size
);

/** What a certificate says, for rawstor_pki_show(). */
struct RawstorPkiInfo {
    /** The SPIFFE ID of the process the certificate is for. */
    char identity[RAWSTOR_PKI_IDENTITY_SIZE];
    /** When it expires, in seconds since the epoch. */
    long long not_after;
    /** Whether the CA given to rawstor_pki_show() signed it: 1 or 0, and -1 if
     * no CA was given. */
    int issued;
    /** Signed tenant role and object restrictions; zero for provider
     * certificates. */
    struct RawstorPkiPermissions permissions;
};

/**
 * Reads the certificate `cert_file` of a process, whoever issued it, and
 * fills `info`; does not change anything. With `dir`, the directory of a CA,
 * it also tells whether that CA signed it; without (NULL), `issued` is -1.
 * This check needs the CA certificate and trust domain, not its private key.
 * Fails with EINVAL if the file is not a certificate that names a process of
 * rawstor, and with ENOENT if it or the CA is not there.
 */
int rawstor_pki_show(
    const char* cert_file, const char* dir, struct RawstorPkiInfo* info
);

/**
 * What went wrong in the last call of this thread that failed, or an empty
 * string. Valid until the next call of one of the functions above.
 */
const char* rawstor_pki_error(void);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_PKI_H
