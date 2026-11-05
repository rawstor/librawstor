#ifndef RAWSTOR_CLI_OUTPUT_H
#define RAWSTOR_CLI_OUTPUT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Getopt codes of the options every data-printing command accepts. */
enum {
    RAWSTOR_CLI_OPT_FORMAT = 1000,
    RAWSTOR_CLI_OPT_COLUMN,
};

/* The usage lines of those options, for a command's own help text. */
#define RAWSTOR_CLI_OUTPUT_USAGE                                               \
    "  --format FORMAT       Output format: table (default), json or "         \
    "value.\n"                                                                 \
    "                        table is a bordered table that wraps long "       \
    "cells to the\n"                                                           \
    "                        terminal width; json is a machine-readable "      \
    "document;\n"                                                              \
    "                        value prints the selected columns "               \
    "tab-separated,\n"                                                         \
    "                        one row per line, without a header.\n"            \
    "  --column COLUMNS      Comma-separated columns to print, in the given "  \
    "order\n"                                                                  \
    "                        (default: all columns)\n"

enum RawstorCliFormat {
    RAWSTOR_CLI_FORMAT_TABLE,
    RAWSTOR_CLI_FORMAT_JSON,
    RAWSTOR_CLI_FORMAT_VALUE,
};

typedef struct RawstorCliOutput {
    enum RawstorCliFormat format;
    /* Comma-separated column names, or NULL for every column. Not owned. */
    const char* columns;
} RawstorCliOutput;

/* Returns 0, or -1 when `name` is not a format. */
int rawstor_cli_output_set_format(RawstorCliOutput* output, const char* name);

enum RawstorCliColumnType {
    RAWSTOR_CLI_COLUMN_STRING,
    /* Right-aligned in a table; a number in json and value. */
    RAWSTOR_CLI_COLUMN_NUMBER,
};

/* One table cell. `text` is what a table shows (NULL: an empty cell, null in
 * json). `number` is what json and value show for a NUMBER column. */
typedef struct RawstorCliCell {
    const char* text;
    uint64_t number;
} RawstorCliCell;

static inline RawstorCliCell rawstor_cli_cell_string(const char* text) {
    RawstorCliCell cell = {text, 0};
    return cell;
}

static inline RawstorCliCell
rawstor_cli_cell_number(const char* text, uint64_t number) {
    RawstorCliCell cell = {text, number};
    return cell;
}

/* An empty `text` is an empty cell (null in json). */
static inline RawstorCliCell rawstor_cli_cell_optional(const char* text) {
    RawstorCliCell cell = {text != NULL && text[0] != '\0' ? text : NULL, 0};
    return cell;
}

/* The object UUID and the bound version UUID of `target`, read off its path
 * without contacting a backend. `version` is empty for a live object, and
 * both are empty when `target` cannot be parsed. */
void rawstor_cli_target_ids(
    const char* target, char* uuid, size_t uuid_size, char* version,
    size_t version_size
);

typedef struct RawstorCliTable RawstorCliTable;

/* `names` are the lowercase column names: json keys and --column values. */
RawstorCliTable* rawstor_cli_table_create(
    const char* name, const char* const* names,
    const enum RawstorCliColumnType* types, size_t ncolumns
);

/* Like rawstor_cli_table_create(), but for a single object: the card has
 * exactly one row, shown as a key/value table, as a json object, and merged
 * into the top-level object of a document with several tables. */
RawstorCliTable* rawstor_cli_record_create(
    const char* name, const char* const* names,
    const enum RawstorCliColumnType* types, size_t ncolumns
);

/* `cells` holds one cell per column; the text is copied. Returns 0 or
 * -ENOMEM. */
int rawstor_cli_table_add_row(
    RawstorCliTable* table, const RawstorCliCell* cells
);

void rawstor_cli_table_delete(RawstorCliTable* table);

/* Prints the tables to stdout. A json document is an array of row objects for
 * one table, a single object for one record, or an object of such arrays keyed
 * by table name for several, with the fields of a record at the top level. A
 * table none of the selected columns belongs to is skipped. Returns an exit
 * code; a column no table has is a usage error reported on stderr. */
int rawstor_cli_output_print(
    const RawstorCliOutput* output, RawstorCliTable* const* tables,
    size_t ntables
);

#ifdef __cplusplus
}
#endif

#endif
