#include "pki.h"

#include "config.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#define DEFAULT_CA_VALIDITY (3650UL * 86400UL)
#define DEFAULT_VALIDITY (7UL * 86400UL)

static void pki_usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor pki <subcommand> [command_options]\n"
        "\n"
        "A small certificate authority for a cluster that has none: init makes "
        "it,\n"
        "issue gives a process its certificate and key, renew replaces them "
        "before\n"
        "they expire. The files are what a process lists as RAWSTOR_TLS_CA, "
        "RAWSTOR_TLS_CERT\n"
        "and RAWSTOR_TLS_KEY. The CA's own key, DIR/ca.key, must not leave "
        "the machine\n"
        "that issues certificates.\n"
        "\n"
        "subcommand:\n"
        "  init                  Create a CA in a directory\n"
        "  issue                 Issue a certificate and a key for an "
        "identity\n"
        "  renew                 Issue a new certificate and key for the "
        "identity of one\n"
        "\n"
        "Run `rawstor pki <subcommand> --help` to show its usage.\n"
    );
}

static void init_usage(void) {
    fprintf(
        stdout,
        "usage: rawstor pki init [--name NAME] [--validity DURATION] DIR\n"
        "\n"
        "Creates the directory DIR (mode 0700) with a new CA: DIR/ca.crt and "
        "DIR/ca.key.\n"
        "\n"
        "options:\n"
        "  --name NAME           Name of the CA (default: rawstor CA)\n"
        "  --validity DURATION   How long the CA is valid (default: 3650d)\n"
        "\n"
        "DURATION is a number with an optional unit: s, m, h or d (seconds "
        "without one).\n"
    );
}

static void issue_usage(void) {
    fprintf(
        stdout,
        "usage: rawstor pki issue --ca DIR --cert FILE --key FILE "
        "[--validity DURATION] IDENTITY\n"
        "\n"
        "Issues a certificate and a new private key for IDENTITY, a SPIFFE "
        "ID:\n"
        "  spiffe://TRUST_DOMAIN/ost/UUID\n"
        "  spiffe://TRUST_DOMAIN/mds/NAME\n"
        "  spiffe://TRUST_DOMAIN/admin/NAME\n"
        "  spiffe://TRUST_DOMAIN/tenant/UUID/client/NAME\n"
        "Existing files are replaced; the key is written with mode 0600.\n"
        "\n"
        "options:\n"
        "  --ca DIR              The CA made by `pki init`\n"
        "  --cert FILE           Where the certificate goes\n"
        "  --key FILE            Where the private key goes\n"
        "  --validity DURATION   How long the certificate is valid "
        "(default: 7d)\n"
    );
}

static void renew_usage(void) {
    fprintf(
        stdout,
        "usage: rawstor pki renew --ca DIR --cert FILE --key FILE "
        "[--validity DURATION]\n"
        "\n"
        "Issues a new certificate and key for the identity of FILE, which the "
        "CA must\n"
        "have issued, over the same files. A running process reads them again "
        "on SIGHUP\n"
        "(`systemctl reload`).\n"
        "\n"
        "options:\n"
        "  --ca DIR              The CA made by `pki init`\n"
        "  --cert FILE           The certificate to renew, and where the new "
        "one goes\n"
        "  --key FILE            Where the new private key goes\n"
        "  --validity DURATION   How long the certificate is valid "
        "(default: 7d)\n"
    );
}

/* "90", "90s", "15m", "12h", "30d" into seconds. Returns 0, or EX_USAGE. */
static int parse_validity(const char* text, unsigned long* seconds) {
    char* end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (end == text || errno != 0 || !isdigit((unsigned char)text[0])) {
        fprintf(stderr, "Invalid validity: %s\n", text);
        return EX_USAGE;
    }
    unsigned long long unit = 1;
    if (*end != '\0') {
        switch (*end) {
        case 's':
            unit = 1;
            break;
        case 'm':
            unit = 60;
            break;
        case 'h':
            unit = 3600;
            break;
        case 'd':
            unit = 86400;
            break;
        default:
            unit = 0;
        }
        if (unit == 0 || end[1] != '\0') {
            fprintf(
                stderr, "Invalid validity: %s (a number, then s, m, h or d)\n",
                text
            );
            return EX_USAGE;
        }
    }
    if (value == 0 || value > ULONG_MAX / unit) {
        fprintf(stderr, "Invalid validity: %s\n", text);
        return EX_USAGE;
    }
    *seconds = (unsigned long)(value * unit);
    return 0;
}

static int report(const char* what, int res) {
    if (res == 0) {
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%s: %s\n", what, rawstor_pki_error());
    return res == -EINVAL ? EX_USAGE : rawstd_exitcode_for_errno(-res);
}

static int command_init(int argc, char** argv) {
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"name", required_argument, NULL, 'n'},
        {"validity", required_argument, NULL, 'V'},
        {},
    };
    const char* name = "rawstor CA";
    unsigned long validity = DEFAULT_CA_VALIDITY;
    optind = 0;
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case 'h':
            init_usage();
            return EXIT_SUCCESS;
        case 'n':
            name = optarg;
            break;
        case 'V': {
            int res = parse_validity(optarg, &validity);
            if (res != 0) {
                return res;
            }
            break;
        }
        default:
            return EX_USAGE;
        }
    }
    if (optind != argc - 1) {
        fprintf(stderr, "A directory is required\n");
        return EX_USAGE;
    }
    return report(
        "Failed to create the CA",
        rawstor_pki_init(argv[optind], name, validity)
    );
}

static int command_issue(int argc, char** argv, int renew) {
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"ca", required_argument, NULL, 'c'},
        {"cert", required_argument, NULL, 'C'},
        {"key", required_argument, NULL, 'k'},
        {"validity", required_argument, NULL, 'V'},
        {},
    };
    const char* ca = NULL;
    const char* cert = NULL;
    const char* key = NULL;
    unsigned long validity = DEFAULT_VALIDITY;
    optind = 0;
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case 'h':
            if (renew) {
                renew_usage();
            } else {
                issue_usage();
            }
            return EXIT_SUCCESS;
        case 'c':
            ca = optarg;
            break;
        case 'C':
            cert = optarg;
            break;
        case 'k':
            key = optarg;
            break;
        case 'V': {
            int res = parse_validity(optarg, &validity);
            if (res != 0) {
                return res;
            }
            break;
        }
        default:
            return EX_USAGE;
        }
    }
    if (ca == NULL || cert == NULL || key == NULL) {
        fprintf(stderr, "--ca, --cert and --key are required\n");
        return EX_USAGE;
    }
    if (renew) {
        if (optind != argc) {
            fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
            return EX_USAGE;
        }
        return report(
            "Failed to renew the certificate",
            rawstor_pki_renew(ca, cert, key, validity)
        );
    }
    if (optind != argc - 1) {
        fprintf(stderr, "An identity is required\n");
        return EX_USAGE;
    }
    return report(
        "Failed to issue the certificate",
        rawstor_pki_issue(ca, argv[optind], validity, cert, key)
    );
}

int rawstor_cli_pki(int argc, char** argv) {
    if (argc < 2) {
        pki_usage();
        return EX_USAGE;
    }
    const char* sub = argv[1];
    if (strcmp(sub, "-h") == 0 || strcmp(sub, "--help") == 0 ||
        strcmp(sub, "help") == 0) {
        pki_usage();
        return EXIT_SUCCESS;
    }
    argc--;
    argv++;
    if (strcmp(sub, "init") == 0) {
        return command_init(argc, argv);
    } else if (strcmp(sub, "issue") == 0) {
        return command_issue(argc, argv, 0);
    } else if (strcmp(sub, "renew") == 0) {
        return command_issue(argc, argv, 1);
    }
    fprintf(stderr, "Unexpected pki subcommand: %s\n", sub);
    return EX_USAGE;
}
