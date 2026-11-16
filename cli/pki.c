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
#include <time.h>

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
        "  show                  Show what a certificate says\n"
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
        "without one).\n" RAWSTOR_CLI_OUTPUT_USAGE "\n"
        "Columns: ca_dir, trust_domain, ca_file (DIR/ca.crt, what a process "
        "lists as\n"
        "RAWSTOR_TLS_CA) and not_after (when the CA expires, UTC).\n"
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
        "  mds [ID]              A rawstor-mds. ID is its id, a UUID like an "
        "OST's; a new\n"
        "                        one is made without it\n"
        "  admin NAME            An operator or a control plane\n"
        "  client TENANT NAME    A tenant's client, such as rawstor-vhost; "
        "TENANT is a UUID\n"
        "\n"
        "options:\n"
        "  --ca DIR              The CA made by `pki init`\n"
        "  --cert FILE           Where the certificate goes\n"
        "  --key FILE            Where the private key goes\n"
        "  --object-rights UUID:MASK\n"
        "                        Restrict one object and its versions "
        "(repeat up to 128 times)\n"
        "                        read=1, write=2, discard=4, manage=8; 0 "
        "denies access.\n"
        "                        The mask intersects the role; other objects "
        "keep role rights.\n"
        "  --role ROLE           Client access: reader, writer or manager\n"
        "                        Required for client certificates\n"
        "  --validity DURATION   How long the certificate is valid "
        "(default: 7d)\n" RAWSTOR_CLI_OUTPUT_USAGE "\n"
        "Columns: identity (the SPIFFE ID), role, trust_domain, id (of an ost "
        "or an mds),\n"
        "name (of an admin or a client), tenant_id (of a client), not_after "
        "(when the\n"
        "certificate expires, UTC) and issued (yes); the ones that do not "
        "apply are empty,\n"
        "null in json. access_role and object_rights show the signed client "
        "permissions.\n"
        "`--format value --column id` prints just an OST's or "
        "an MDS's id.\n"
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
        "Preserves the signed access role and object restrictions; use issue "
        "to change them.\n"
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

static void show_usage(void) {
    fprintf(
        stdout,
        "usage: rawstor pki show --cert FILE [--ca DIR]\n"
        "\n"
        "Shows what the certificate of a process says, whoever issued it, and "
        "changes\n"
        "nothing. With --ca it also tells whether that CA signed it.\n"
        "\n"
        "options:\n"
        "  --cert FILE           The certificate\n"
        "  --ca DIR              A CA made by `pki init`: fills the issued "
        "column (yes or no)\n" RAWSTOR_CLI_OUTPUT_USAGE "\n"
        "Columns are those of `pki issue`; issued is empty without --ca.\n"
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

/* `seconds` since the epoch as 2036-11-13T10:56:28Z. */
static void format_time(long long seconds, char* buf, size_t size) {
    buf[0] = '\0';
    time_t t = (time_t)seconds;
    struct tm utc;
    if (gmtime_r(&t, &utc) != NULL) {
        strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &utc);
    }
}

static int report(const char* what, int res) {
    if (res == 0) {
        return EXIT_SUCCESS;
    }
    fprintf(stderr, "%s: %s\n", what, rawstor_pki_error());
    return res == -EINVAL ? EX_USAGE : rawstd_exitcode_for_errno(-res);
}

static const char* const ca_columns[] = {
    "ca_dir",
    "trust_domain",
    "ca_file",
    "not_after",
};
static const enum RawstorCliColumnType ca_types[] = {
    RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING,
};
#define CA_NCOLUMNS (sizeof(ca_columns) / sizeof(ca_columns[0]))

static int command_init(int argc, char** argv) {
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"trust-domain", required_argument, NULL, 'd'},
        {"validity", required_argument, NULL, 'V'},
        {"format", required_argument, NULL, RAWSTOR_CLI_OPT_FORMAT},
        {"column", required_argument, NULL, RAWSTOR_CLI_OPT_COLUMN},
        {},
    };
    RawstorCliOutput output = {};
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
    if (trust_domain == NULL) {
        fprintf(stderr, "--trust-domain is required\n");
        return EX_USAGE;
    }
    if (optind != argc - 1) {
        fprintf(stderr, "A directory is required\n");
        return EX_USAGE;
    }
    const char* dir = argv[optind];

    /* A bad --column is refused before the CA is made, not after. */
    RawstorCliTable* table =
        rawstor_cli_record_create("pki", ca_columns, ca_types, CA_NCOLUMNS);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    int checked = rawstor_cli_output_check(&output, &table, 1);
    if (checked != EXIT_SUCCESS) {
        rawstor_cli_table_delete(table);
        return checked;
    }

    time_t now = time(NULL);
    int res = rawstor_pki_init(dir, trust_domain, validity);
    if (res != 0) {
        rawstor_cli_table_delete(table);
        return report("Failed to create the CA", res);
    }

    /* The CA is valid from now for `validity` seconds, to the second. */
    char not_after[32];
    format_time(
        (long long)now + (long long)validity, not_after, sizeof(not_after)
    );
    char ca_file[4096];
    snprintf(ca_file, sizeof(ca_file), "%s/ca.crt", dir);

    RawstorCliCell cells[] = {
        rawstor_cli_cell_string(dir),
        rawstor_cli_cell_string(trust_domain),
        rawstor_cli_cell_string(ca_file),
        rawstor_cli_cell_optional(not_after),
    };
    int ret = EXIT_FAILURE;
    if (rawstor_cli_table_add_row(table, cells) < 0) {
        fprintf(stderr, "Out of memory\n");
    } else {
        ret = rawstor_cli_output_print(&output, &table, 1);
    }
    rawstor_cli_table_delete(table);
    return ret;
}

/* The role and its names from the arguments after the options: `ost [ID]`,
 * `mds [ID]`, `admin NAME`, `client TENANT NAME`. Returns 0, or EX_USAGE. */
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
        min = 0;
        max = 1;
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
            *role == RAWSTOR_PKI_CLIENT ? "a tenant and a name" : "a name"
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
    "identity",  "role",      "trust_domain", "id",          "name",
    "tenant_id", "not_after", "issued",       "access_role", "object_rights",
};
static const enum RawstorCliColumnType identity_types[] = {
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
};
#define IDENTITY_NCOLUMNS                                                      \
    (sizeof(identity_columns) / sizeof(identity_columns[0]))

/* The table of one process, from what its certificate says. The library has
 * checked the shape of the ID:
 *   spiffe://<trust domain>/ost/<id>
 *   spiffe://<trust domain>/mds/<id>
 *   spiffe://<trust domain>/admin/<name>
 *   spiffe://<trust domain>/tenant/<tenant>/client/<name>
 */
static RawstorCliTable* identity_table(const struct RawstorPkiInfo* info) {
    char text[RAWSTOR_PKI_IDENTITY_SIZE];
    snprintf(text, sizeof(text), "%s", info->identity);

    const char* domain = text + strlen("spiffe://");
    char* path = strchr(text + strlen("spiffe://"), '/');
    *path++ = '\0';
    const char* role = path;
    const char* id = "";
    const char* name = "";
    const char* tenant_id = "";
    char* slash = strchr(path, '/');
    *slash++ = '\0';
    if (strcmp(role, "ost") == 0 || strcmp(role, "mds") == 0) {
        id = slash;
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
    char not_after[32];
    format_time(info->not_after, not_after, sizeof(not_after));
    const char* issued = info->issued < 0 ? "" : info->issued ? "yes" : "no";

    RawstorCliTable* table = rawstor_cli_record_create(
        "pki", identity_columns, identity_types, IDENTITY_NCOLUMNS
    );
    if (table == NULL) {
        return NULL;
    }
    const char* access_role =
        info->permissions.role == RAWSTOR_ROLE_READER    ? "reader"
        : info->permissions.role == RAWSTOR_ROLE_WRITER  ? "writer"
        : info->permissions.role == RAWSTOR_ROLE_MANAGER ? "manager"
                                                         : "";
    char object_rights[RAWSTOR_PKI_MAX_OBJECT_RIGHTS * 41 + 1] = {0};
    size_t used = 0;
    for (size_t i = 0; i < info->permissions.count; ++i) {
        const struct RawstorPkiObjectRights* entry =
            &info->permissions.objects[i];
        used += (size_t)snprintf(
            object_rights + used, sizeof(object_rights) - used, "%s%s:%u",
            i ? "," : "", entry->object_id, entry->rights
        );
    }
    RawstorCliCell cells[] = {
        rawstor_cli_cell_string(info->identity),
        rawstor_cli_cell_string(role),
        rawstor_cli_cell_string(domain),
        rawstor_cli_cell_optional(id),
        rawstor_cli_cell_optional(name),
        rawstor_cli_cell_optional(tenant_id),
        rawstor_cli_cell_optional(not_after),
        rawstor_cli_cell_optional(issued),
        rawstor_cli_cell_optional(access_role),
        rawstor_cli_cell_optional(object_rights),
    };
    if (rawstor_cli_table_add_row(table, cells) < 0) {
        rawstor_cli_table_delete(table);
        return NULL;
    }
    return table;
}

/* Checks --column, so that a command can refuse a bad one before it changes
 * anything. Returns 0, or a usage error reported on stderr. */
static int check_output(const RawstorCliOutput* output) {
    RawstorCliTable* probe = rawstor_cli_record_create(
        "pki", identity_columns, identity_types, IDENTITY_NCOLUMNS
    );
    if (probe == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    int checked = rawstor_cli_output_check(output, &probe, 1);
    rawstor_cli_table_delete(probe);
    return checked;
}

static int print_certificate(
    const RawstorCliOutput* output, const char* cert, const char* ca
) {
    struct RawstorPkiInfo info;
    int res = rawstor_pki_show(cert, ca, &info);
    if (res != 0) {
        return report("Failed to read the certificate", res);
    }
    RawstorCliTable* table = identity_table(&info);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    int ret = rawstor_cli_output_print(output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
}

static int command_issue(int argc, char** argv, int renew) {
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"ca", required_argument, NULL, 'c'},
        {"cert", required_argument, NULL, 'C'},
        {"key", required_argument, NULL, 'k'},
        {"validity", required_argument, NULL, 'V'},
        {"role", required_argument, NULL, 'r'},
        {"object-rights", required_argument, NULL, 'o'},
        {"format", required_argument, NULL, RAWSTOR_CLI_OPT_FORMAT},
        {"column", required_argument, NULL, RAWSTOR_CLI_OPT_COLUMN},
        {},
    };
    RawstorCliOutput output = {};
    const char* ca = NULL;
    const char* cert = NULL;
    const char* key = NULL;
    unsigned long validity = DEFAULT_VALIDITY;
    struct RawstorPkiPermissions permissions = {0};
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
        case 'r':
            if (renew) {
                fprintf(
                    stderr,
                    "renew preserves permissions; use issue to change them\n"
                );
                return EX_USAGE;
            }
            if (!strcmp(optarg, "reader"))
                permissions.role = RAWSTOR_ROLE_READER;
            else if (!strcmp(optarg, "writer"))
                permissions.role = RAWSTOR_ROLE_WRITER;
            else if (!strcmp(optarg, "manager"))
                permissions.role = RAWSTOR_ROLE_MANAGER;
            else {
                fprintf(stderr, "--role must be reader, writer or manager\n");
                return EX_USAGE;
            }
            break;
        case 'o': {
            const char* separator = strchr(optarg, ':');
            char* end = NULL;
            if (renew || !separator || separator - optarg != 36 ||
                permissions.count == RAWSTOR_PKI_MAX_OBJECT_RIGHTS) {
                fprintf(
                    stderr, "--object-rights requires UUID:MASK (at most 128 "
                            "entries); use issue to change permissions\n"
                );
                return EX_USAGE;
            }
            errno = 0;
            unsigned long mask = strtoul(separator + 1, &end, 10);
            if (!separator[1] || *end || errno || mask > RAWSTOR_PERM_ALL) {
                fprintf(stderr, "MASK must be 0..15\n");
                return EX_USAGE;
            }
            struct RawstorPkiObjectRights* entry =
                &permissions.objects[permissions.count++];
            memcpy(entry->object_id, optarg, 36);
            entry->object_id[36] = '\0';
            entry->rights = (unsigned int)mask;
            break;
        }
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
     * the only thing left to report is the certificate, and a retry would issue
     * another key. */
    int checked = check_output(&output);
    if (checked != EXIT_SUCCESS) {
        return checked;
    }

    int res;
    if (renew) {
        if (optind != argc) {
            fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
            return EX_USAGE;
        }
        res = rawstor_pki_renew(ca, cert, key, validity, NULL, 0);
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
        if ((role == RAWSTOR_PKI_CLIENT && !permissions.role) ||
            (role != RAWSTOR_PKI_CLIENT &&
             (permissions.role || permissions.count))) {
            fprintf(
                stderr,
                "--role is required for a client and applies only to clients\n"
            );
            return EX_USAGE;
        }
        res = rawstor_pki_issue(
            ca, role, tenant, name, validity, cert, key, NULL, 0, &permissions
        );
        if (res != 0) {
            return report("Failed to issue the certificate", res);
        }
    }
    /* What was written, read back: the certificate's own word for it. */
    return print_certificate(&output, cert, ca);
}

static int command_show(int argc, char** argv) {
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"ca", required_argument, NULL, 'c'},
        {"cert", required_argument, NULL, 'C'},
        {"format", required_argument, NULL, RAWSTOR_CLI_OPT_FORMAT},
        {"column", required_argument, NULL, RAWSTOR_CLI_OPT_COLUMN},
        {},
    };
    RawstorCliOutput output = {};
    const char* ca = NULL;
    const char* cert = NULL;
    optind = 0;
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case 'h':
            show_usage();
            return EXIT_SUCCESS;
        case 'c':
            ca = optarg;
            break;
        case 'C':
            cert = optarg;
            break;
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
    if (cert == NULL) {
        fprintf(stderr, "--cert is required\n");
        return EX_USAGE;
    }
    if (optind != argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EX_USAGE;
    }
    int checked = check_output(&output);
    if (checked != EXIT_SUCCESS) {
        return checked;
    }
    return print_certificate(&output, cert, ca);
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
    } else if (strcmp(sub, "show") == 0) {
        return command_show(argc, argv);
    }
    fprintf(stderr, "Unexpected pki subcommand: %s\n", sub);
    return EX_USAGE;
}
