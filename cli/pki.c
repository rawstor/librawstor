#include "pki.h"

#include "config.h"
#include "output.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
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
        "it for\n"
        "the trust domain of the cluster, issue gives a process its "
        "certificate and key,\n"
        "renew replaces them before they expire. The files are what a process "
        "lists as\n"
        "RAWSTOR_TLS_CA, RAWSTOR_TLS_CERT and RAWSTOR_TLS_KEY. The CA's own "
        "key,\n"
        "DIR/ca.key, must not leave the machine that issues certificates.\n"
        "\n"
        "subcommand:\n"
        "  init                  Create a CA in a directory\n"
        "  issue                 Issue a certificate and a key for a process\n"
        "  renew                 Issue a new certificate and key for the "
        "process of one\n"
        "\n"
        "Run `rawstor pki <subcommand> --help` to show its usage.\n"
    );
}

static void init_usage(void) {
    fprintf(
        stdout,
        "usage: rawstor pki init --trust-domain DOMAIN [--validity DURATION] "
        "DIR\n"
        "\n"
        "Creates the directory DIR (mode 0700) with a new CA for DOMAIN: "
        "DIR/ca.crt,\n"
        "DIR/ca.key and DIR/trust_domain. It is the CA of one cluster, and "
        "every certificate\n"
        "it issues is in DOMAIN.\n"
        "\n"
        "options:\n"
        "  --trust-domain DOMAIN The trust domain of the cluster, lowercase "
        "letters, digits,\n"
        "                        '.', '-' and '_' (RAWSTOR_TLS_TRUST_DOMAIN)\n"
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
        "[--validity DURATION] <process>\n"
        "\n"
        "Issues a certificate and a new private key for a process, replacing "
        "the files; the\n"
        "key is written with mode 0600. Prints the SPIFFE ID the certificate "
        "names.\n"
        "\n"
        "process:\n"
        "  ost [ID]              A rawstor-ost. ID is its id in the MDS "
        "topology, a UUID;\n"
        "                        a new one is made without it\n"
        "  mds NAME              A rawstor-mds\n"
        "  admin NAME            An operator or a control plane\n"
        "  client TENANT NAME    A tenant's client, such as rawstor-vhost; "
        "TENANT is a UUID\n"
        "\n"
        "options:\n"
        "  --ca DIR              The CA made by `pki init`\n"
        "  --cert FILE           Where the certificate goes\n"
        "  --key FILE            Where the private key goes\n"
        "  --validity DURATION   How long the certificate is valid "
        "(default: 7d)\n" RAWSTOR_CLI_OUTPUT_USAGE "\n"
        "Columns: identity (the SPIFFE ID), role, trust_domain, name (of an "
        "mds, "
        "an admin or\n"
        "a client), ost_id (of an ost) and tenant_id (of a client); the ones "
        "that do not\n"
        "apply are empty, null in json. `--format value --column ost_id` "
        "prints just an OST's id.\n"
    );
}

static void renew_usage(void) {
    fprintf(
        stdout,
        "usage: rawstor pki renew --ca DIR --cert FILE --key FILE "
        "[--validity DURATION]\n"
        "\n"
        "Issues a new certificate and key for the process FILE was issued "
        "for, which the CA\n"
        "must have issued, over the same files. A running process reads them "
        "again on\n"
        "SIGHUP (`systemctl reload`). Prints the SPIFFE ID.\n"
        "\n"
        "options:\n"
        "  --ca DIR              The CA made by `pki init`\n"
        "  --cert FILE           The certificate to renew, and where the new "
        "one goes\n"
        "  --key FILE            Where the new private key goes\n"
        "  --validity DURATION   How long the certificate is valid "
        "(default: 7d)\n" RAWSTOR_CLI_OUTPUT_USAGE "\n"
        "Columns are those of `pki issue`.\n"
    );
}

/* A validity in seconds from "90", "90s", "15m", "12h" or "30d". Returns 0, or
 * EX_USAGE. */
static int parse_validity(const char* text, unsigned long* seconds) {
    uint64_t value;
    int res = rawstd_duration_to_seconds(text, &value);
    if (res != 0 || value == 0 || value > ULONG_MAX) {
        fprintf(
            stderr, "Invalid validity: %s (a number, then s, m, h or d)\n", text
        );
        return EX_USAGE;
    }
    *seconds = (unsigned long)value;
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
        {"trust-domain", required_argument, NULL, 'd'},
        {"validity", required_argument, NULL, 'V'},
        {},
    };
    const char* trust_domain = NULL;
    unsigned long validity = DEFAULT_CA_VALIDITY;
    optind = 0;
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case 'h':
            init_usage();
            return EXIT_SUCCESS;
        case 'd':
            trust_domain = optarg;
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
    if (trust_domain == NULL) {
        fprintf(stderr, "--trust-domain is required\n");
        return EX_USAGE;
    }
    if (optind != argc - 1) {
        fprintf(stderr, "A directory is required\n");
        return EX_USAGE;
    }
    return report(
        "Failed to create the CA",
        rawstor_pki_init(argv[optind], trust_domain, validity)
    );
}

/* The role and its names from the arguments after the options: `ost [ID]`,
 * `mds NAME`, `admin NAME`, `client TENANT NAME`. Returns 0, or EX_USAGE. */
static int parse_process(
    int argc, char** argv, enum RawstorPkiRole* role, const char** tenant,
    const char** name
) {
    if (optind == argc) {
        fprintf(stderr, "A process is required: ost, mds, admin or client\n");
        return EX_USAGE;
    }
    const char* kind = argv[optind++];
    int rest = argc - optind;
    *tenant = NULL;
    *name = NULL;
    int min;
    int max;
    if (strcmp(kind, "ost") == 0) {
        *role = RAWSTOR_PKI_OST;
        min = 0;
        max = 1;
    } else if (strcmp(kind, "mds") == 0) {
        *role = RAWSTOR_PKI_MDS;
        min = max = 1;
    } else if (strcmp(kind, "admin") == 0) {
        *role = RAWSTOR_PKI_ADMIN;
        min = max = 1;
    } else if (strcmp(kind, "client") == 0) {
        *role = RAWSTOR_PKI_CLIENT;
        min = max = 2;
    } else {
        fprintf(
            stderr, "Unknown process: %s (ost, mds, admin or client)\n", kind
        );
        return EX_USAGE;
    }
    if (rest < min) {
        fprintf(
            stderr, "%s needs %s\n", kind,
            *role == RAWSTOR_PKI_CLIENT ? "a tenant and a name"
            : *role == RAWSTOR_PKI_OST  ? "nothing or an id"
                                        : "a name"
        );
        return EX_USAGE;
    }
    if (rest > max) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind + max]);
        return EX_USAGE;
    }
    if (*role == RAWSTOR_PKI_CLIENT) {
        *tenant = argv[optind];
        *name = argv[optind + 1];
    } else if (rest == 1) {
        *name = argv[optind];
    }
    return 0;
}

static const char* const identity_columns[] = {
    "identity", "role", "trust_domain", "name", "ost_id", "tenant_id",
};
static const enum RawstorCliColumnType identity_types[] = {
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
};
#define IDENTITY_NCOLUMNS                                                      \
    (sizeof(identity_columns) / sizeof(identity_columns[0]))

/* The table of one process, from the SPIFFE ID the CA printed:
 *   spiffe://<trust domain>/ost/<id>
 *   spiffe://<trust domain>/mds/<name>
 *   spiffe://<trust domain>/admin/<name>
 *   spiffe://<trust domain>/tenant/<tenant>/client/<name>
 * The CA made the ID, so its shape is known. */
static RawstorCliTable* identity_table(const char* identity) {
    char text[RAWSTOR_PKI_IDENTITY_SIZE];
    snprintf(text, sizeof(text), "%s", identity);

    const char* domain = text + strlen("spiffe://");
    char* path = strchr(text + strlen("spiffe://"), '/');
    *path++ = '\0';
    const char* role = path;
    const char* name = "";
    const char* ost_id = "";
    const char* tenant_id = "";
    char* slash = strchr(path, '/');
    *slash++ = '\0';
    if (strcmp(role, "ost") == 0) {
        ost_id = slash;
    } else if (strcmp(role, "tenant") == 0) {
        /* tenant/<tenant>/client/<name> */
        role = "client";
        tenant_id = slash;
        char* rest = strchr(slash, '/');
        *rest++ = '\0';
        name = strchr(rest, '/') + 1;
    } else {
        name = slash;
    }

    RawstorCliTable* table = rawstor_cli_record_create(
        "pki", identity_columns, identity_types, IDENTITY_NCOLUMNS
    );
    if (table == NULL) {
        return NULL;
    }
    RawstorCliCell cells[] = {
        rawstor_cli_cell_string(identity), rawstor_cli_cell_string(role),
        rawstor_cli_cell_string(domain),   rawstor_cli_cell_optional(name),
        rawstor_cli_cell_optional(ost_id), rawstor_cli_cell_optional(tenant_id),
    };
    if (rawstor_cli_table_add_row(table, cells) < 0) {
        rawstor_cli_table_delete(table);
        return NULL;
    }
    return table;
}

static int command_issue(int argc, char** argv, int renew) {
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"ca", required_argument, NULL, 'c'},
        {"cert", required_argument, NULL, 'C'},
        {"key", required_argument, NULL, 'k'},
        {"validity", required_argument, NULL, 'V'},
        {"format", required_argument, NULL, RAWSTOR_CLI_OPT_FORMAT},
        {"column", required_argument, NULL, RAWSTOR_CLI_OPT_COLUMN},
        {},
    };
    RawstorCliOutput output = {};
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
        case RAWSTOR_CLI_OPT_FORMAT:
            if (rawstor_cli_output_set_format(&output, optarg) != 0) {
                fprintf(
                    stderr, "Unknown format: %s (table, json or value)\n",
                    optarg
                );
                return EX_USAGE;
            }
            break;
        case RAWSTOR_CLI_OPT_COLUMN:
            output.columns = optarg;
            break;
        default:
            return EX_USAGE;
        }
    }
    if (ca == NULL || cert == NULL || key == NULL) {
        fprintf(stderr, "--ca, --cert and --key are required\n");
        return EX_USAGE;
    }

    /* A bad --column is refused before a certificate is issued: afterwards
     * the only thing left to report is the identity, and a retry would issue
     * another key. */
    RawstorCliTable* probe = rawstor_cli_record_create(
        "pki", identity_columns, identity_types, IDENTITY_NCOLUMNS
    );
    if (probe == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    int checked = rawstor_cli_output_check(&output, &probe, 1);
    rawstor_cli_table_delete(probe);
    if (checked != EXIT_SUCCESS) {
        return checked;
    }

    char identity[RAWSTOR_PKI_IDENTITY_SIZE];
    int res;
    if (renew) {
        if (optind != argc) {
            fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
            return EX_USAGE;
        }
        res = rawstor_pki_renew(
            ca, cert, key, validity, identity, sizeof(identity)
        );
        if (res != 0) {
            return report("Failed to renew the certificate", res);
        }
    } else {
        enum RawstorPkiRole role;
        const char* tenant;
        const char* name;
        res = parse_process(argc, argv, &role, &tenant, &name);
        if (res != 0) {
            return res;
        }
        res = rawstor_pki_issue(
            ca, role, tenant, name, validity, cert, key, identity,
            sizeof(identity)
        );
        if (res != 0) {
            return report("Failed to issue the certificate", res);
        }
    }
    RawstorCliTable* table = identity_table(identity);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    int ret = rawstor_cli_output_print(&output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
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
