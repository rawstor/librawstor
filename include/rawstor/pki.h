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
    /** A rawstor-ost; `name` is its id, the one in the MDS topology. */
    RAWSTOR_PKI_OST,
    /** A rawstor-mds; `name` is its name. */
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

/**
 * Issues a certificate and a new private key for a process of `role`, valid
 * for `validity` seconds, into `cert_file` and `key_file`, replacing what is
 * there; the key is written with mode 0600. The old pair stays if the new one
 * cannot be written.
 *
 * `tenant` is for a client only and NULL otherwise. `name` may be NULL for an
 * OST, which then gets a new id. The SPIFFE ID the certificate names (see
 * docs/security.md) is copied to `identity`, if it is not NULL, with room for
 * RAWSTOR_PKI_IDENTITY_SIZE bytes: `size` is checked before anything is
 * issued.
 */
int rawstor_pki_issue(
    const char* dir, enum RawstorPkiRole role, const char* tenant,
    const char* name, unsigned long validity, const char* cert_file,
    const char* key_file, char* identity, size_t size
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

/**
 * What went wrong in the last call of this thread that failed, or an empty
 * string. Valid until the next call of one of the functions above.
 */
const char* rawstor_pki_error(void);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_PKI_H
