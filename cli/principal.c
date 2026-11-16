#include "config.h"

#include "output.h"
#include "principal.h"
#include "rawio_sync.h"
#include <rawstd/exitcode.h>
#include <rawstor/principal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

static void principal_usage(const char* command) {
    printf("Rawstor CLI " PACKAGE_VERSION "\n\nAccess administration\n\n");
    if (!command || !strcmp(command, "set")) {
        printf(
            "Usage: rawstor access set [LOCATION] ID reader|writer|manager\n"
            "       rawstor access set [LOCATION] ID rights OBJECT MASK\n\n"
            "Set a tenant principal role or restrict access to one object.\n"
            "  reader   Read objects and versions.\n"
            "  writer   Read, write and discard object data.\n"
            "  manager  Writer rights plus object and version management.\n"
            "MASK combines read=1, write=2, discard=4, manage=8 (0 denies "
            "access).\n"
            "Object restrictions intersect the principal's role.\n\n"
        );
    }
    if (!command || !strcmp(command, "remove")) {
        printf(
            "Usage: rawstor access remove [LOCATION] ID [OBJECT]\n\n"
            "Remove a principal, or remove one object restriction to restore "
            "role rights.\n\n"
        );
    }
    if (!command || !strcmp(command, "list")) {
        printf(
            "Usage: rawstor access list [LOCATION] [OPTIONS]\n\n"
            "List principal roles and object restrictions.\n"
            "Columns: identity, role, object_id, "
            "rights.\n" RAWSTOR_CLI_OUTPUT_USAGE "\n"
        );
    }
    printf(
        "LOCATION is one mds:// address; defaults to RAWSTOR_LOCATION.\n"
        "An explicit LOCATION takes precedence over the environment.\n"
        "ID is spiffe://DOMAIN/tenant/TENANT_UUID/client/NAME.\n"
        "OBJECT is an object UUID. Provider admin credentials are required.\n"
        "Changes apply to new capabilities; existing tokens last until "
        "expiry.\n"
        "  -h, --help  Show help for this command.\n\n"
        "Examples:\n"
        "  rawstor access list mds://localhost:7776\n"
        "  RAWSTOR_LOCATION=mds://localhost:7776 rawstor access list\n"
        "  rawstor access set mds://localhost:7776 "
        "spiffe://cluster.example/tenant/00000000-0000-0000-0000-000000000001/"
        "client/app reader\n"
    );
}

int rawstor_cli_principal(int argc, char** argv) {
    if (argc < 2) {
        principal_usage(NULL);
        return EX_USAGE;
    }
    if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        principal_usage(NULL);
        return EXIT_SUCCESS;
    }
    const char* command = argv[1];
    int list = !strcmp(command, "list");
    if (!list && strcmp(command, "set") && strcmp(command, "remove")) {
        fprintf(stderr, "Unknown access command: %s\n", command);
        principal_usage(NULL);
        return EX_USAGE;
    }
    RawstorCliOutput output = {0};
    char* positional[5];
    int npos = 0;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            principal_usage(command);
            return EXIT_SUCCESS;
        }
        if (list && !strcmp(argv[i], "--format") && i + 1 < argc) {
            if (rawstor_cli_output_set_format(&output, argv[++i]))
                return EX_USAGE;
        } else if (list && !strcmp(argv[i], "--column") && i + 1 < argc) {
            output.columns = argv[++i];
        } else if (npos < 5 && argv[i][0] != '-') {
            positional[npos++] = argv[i];
        } else {
            principal_usage(command);
            return EX_USAGE;
        }
    }
    const char* location = getenv("RAWSTOR_LOCATION");
    int explicit_location =
        npos && (list || (strstr(positional[0], "://") &&
                          strncmp(positional[0], "spiffe://", 9)));
    if (explicit_location)
        location = positional[0];
    if (!location || !*location) {
        fprintf(stderr, "Specify LOCATION or set RAWSTOR_LOCATION.\n");
        principal_usage(command);
        return EX_USAGE;
    }
    int arguments = npos - explicit_location;
    if ((list && arguments != 0) ||
        (!strcmp(command, "remove") && arguments != 1 && arguments != 2) ||
        (!strcmp(command, "set") && arguments != 2 && arguments != 4)) {
        principal_usage(command);
        return EX_USAGE;
    }
    // Normalize optional LOCATION so all operations share the same dispatch.
    char* normalized[7] = {argv[0], argv[1], (char*)location};
    argc = 3;
    for (int i = explicit_location; i < npos; ++i)
        normalized[argc++] = positional[i];
    argv = normalized;
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0)
        return rawstd_exitcode_for_errno(-res);
    struct RawstorPrincipal* entries = NULL;
    size_t count = 0;
    if (!strcmp(command, "list") && argc == 3) {
        res = rawstor_principal_list(
            op.queue, location, &entries, &count, rawstor_cli_op_cb, &op
        );
    } else if (!strcmp(command, "remove") && (argc == 4 || argc == 5)) {
        res = rawstor_principal_remove(
            op.queue, location, argv[3], argc == 5 ? argv[4] : NULL,
            rawstor_cli_op_cb, &op
        );
    } else if (!strcmp(command, "set") && (argc == 5 || argc == 7)) {
        unsigned int role = 0, rights = 0;
        const char* object = NULL;
        if (argc == 7 && !strcmp(argv[4], "rights")) {
            char* end;
            unsigned long mask = strtoul(argv[6], &end, 10);
            if (!*argv[6] || *end || mask > RAWSTOR_RIGHT_ALL) {
                rawstor_cli_op_destroy(&op);
                return EX_USAGE;
            }
            rights = (unsigned int)mask;
            object = argv[5];
        } else if (argc == 5) {
            if (!strcmp(argv[4], "reader"))
                role = RAWSTOR_PRINCIPAL_READER;
            else if (!strcmp(argv[4], "writer"))
                role = RAWSTOR_PRINCIPAL_WRITER;
            else if (!strcmp(argv[4], "manager"))
                role = RAWSTOR_PRINCIPAL_MANAGER;
        }
        if (!role && !object) {
            rawstor_cli_op_destroy(&op);
            return EX_USAGE;
        }
        res = rawstor_principal_set(
            op.queue, location, argv[3], role, object, rights,
            rawstor_cli_op_cb, &op
        );
    } else {
        rawstor_cli_op_destroy(&op);
        return EX_USAGE;
    }
    ssize_t result = rawstor_cli_op_wait(&op, res);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        rawstor_principal_list_delete(entries);
        fprintf(
            stderr, "Principal operation failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }
    if (entries) {
        const char* columns[] = {"identity", "role", "object_id", "rights"};
        const enum RawstorCliColumnType types[] = {
            RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
            RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_NUMBER
        };
        RawstorCliTable* table =
            rawstor_cli_table_create("principals", columns, types, 4);
        if (!table) {
            rawstor_principal_list_delete(entries);
            return EXIT_FAILURE;
        }
        for (size_t i = 0; i < count; ++i) {
            struct RawstorPrincipal* entry = &entries[i];
            char rights[16];
            snprintf(rights, sizeof(rights), "%u", entry->rights);
            const char* role =
                entry->role == RAWSTOR_PRINCIPAL_READER    ? "reader"
                : entry->role == RAWSTOR_PRINCIPAL_WRITER  ? "writer"
                : entry->role == RAWSTOR_PRINCIPAL_MANAGER ? "manager"
                                                           : "";
            RawstorCliCell cells[] = {
                rawstor_cli_cell_string(entry->identity),
                rawstor_cli_cell_optional(role),
                rawstor_cli_cell_optional(entry->object_id),
                rawstor_cli_cell_number(rights, entry->rights)
            };
            if (rawstor_cli_table_add_row(table, cells) < 0) {
                rawstor_cli_table_delete(table);
                rawstor_principal_list_delete(entries);
                return EXIT_FAILURE;
            }
        }
        int printed = rawstor_cli_output_print(&output, &table, 1);
        rawstor_cli_table_delete(table);
        rawstor_principal_list_delete(entries);
        return printed;
    }
    return EXIT_SUCCESS;
}
