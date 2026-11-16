#include "principal.h"
#include "output.h"
#include "rawio_sync.h"
#include <rawstd/exitcode.h>
#include <rawstor/principal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

int rawstor_cli_principal(int argc, char** argv) {
    if (argc < 3 || !strcmp(argv[1], "--help")) {
        fprintf(
            stderr,
            "usage: rawstor principal set LOCATION ID reader|writer|manager\n"
            "       rawstor principal set LOCATION ID rights OBJECT MASK\n"
            "       rawstor principal remove LOCATION ID [OBJECT]\n"
            "       rawstor principal list LOCATION\n"
            "MASK is a bitmask: read=1, write=2, discard=4, manage=8.\n"
        );
        return argc > 1 && !strcmp(argv[1], "--help") ? EXIT_SUCCESS : EX_USAGE;
    }
    const char* command = argv[1];
    const char* location = argv[2];
    RawstorCliOutput output = {0};
    if (!strcmp(command, "list")) {
        for (int i = 3; i < argc; ++i) {
            if (!strcmp(argv[i], "--format") && i + 1 < argc) {
                if (rawstor_cli_output_set_format(&output, argv[++i]))
                    return EX_USAGE;
            } else if (!strcmp(argv[i], "--column") && i + 1 < argc) {
                output.columns = argv[++i];
            } else
                return EX_USAGE;
        }
        argc = 3;
    }
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
