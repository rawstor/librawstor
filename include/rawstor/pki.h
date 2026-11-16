/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_PKI_H
#define RAWSTOR_PKI_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A small certificate authority for installations that have none: a directory
 * with the CA certificate, `ca.crt`, which every process lists as
 * RAWSTOR_TLS_CA, and its private key, `ca.key`, readable by its owner only.
 * It issues the certificates a process needs for RAWSTOR_TLS_CERT and
 * RAWSTOR_TLS_KEY, see docs/configuration.md.
 *
 * None of these functions needs rawstor_initialize(), so a program can make
 * its certificates before it starts rawstor with them. Every one returns 0, or
 * a negative errno: EEXIST for an init over an existing CA, ENOENT for a CA or
 * a certificate that is not there, EINVAL for a bad identity, a bad validity
 * or a certificate this CA did not issue. rawstor_pki_error() tells more.
 */

/**
 * Creates the directory `dir` (mode 0700) with a new CA named `name`, valid
 * for `validity` seconds. Refuses to touch a directory that has a CA.
 */
int rawstor_pki_init(const char* dir, const char* name, unsigned long validity);

/**
 * Issues a certificate and a new private key for `identity`, a SPIFFE ID of
 * rawstor (spiffe://<trust domain>/ost/<uuid>, /mds/<name>, /admin/<name> or
 * /tenant/<uuid>/client/<name>), valid for `validity` seconds, into
 * `cert_file` and `key_file`. An existing file is replaced; the key is
 * written with mode 0600.
 */
int rawstor_pki_issue(
    const char* dir, const char* identity, unsigned long validity,
    const char* cert_file, const char* key_file
);

/**
 * Issues a new certificate and key for the identity of `cert_file`, which the
 * CA in `dir` must have issued, over the same files. A process picks them up
 * when it is told to reload its certificate.
 */
int rawstor_pki_renew(
    const char* dir, const char* cert_file, const char* key_file,
    unsigned long validity
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
