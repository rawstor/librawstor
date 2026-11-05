#include "output.h"

#include <nlohmann/json.hpp>

#include <rawstor.h>

#include <sys/ioctl.h>
#include <sysexits.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <sstream>
#include <string>
#include <vector>

struct RawstorCliTable {
    std::string name;
    bool record = false;
    std::vector<std::string> names;
    std::vector<RawstorCliColumnType> types;
    // Per row and column: the displayed text (nullopt-like flag in `nulls`)
    // and the raw number.
    std::vector<std::vector<std::string>> texts;
    std::vector<std::vector<bool>> nulls;
    std::vector<std::vector<uint64_t>> numbers;
};

namespace {

using json = nlohmann::ordered_json;

struct Glyphs {
    const char* horizontal;
    const char* vertical;
    // [top|middle|bottom][left|middle|right]
    const char* cross[3][3];
};

const Glyphs unicode_glyphs = {
    "─",
    "│",
    {{"┌", "┬", "┐"}, {"├", "┼", "┤"}, {"└", "┴", "┘"}},
};

const Glyphs ascii_glyphs = {
    "-",
    "|",
    {{"+", "+", "+"}, {"+", "+", "+"}, {"+", "+", "+"}},
};

bool locale_is_utf8() {
    for (const char* var : {"LC_ALL", "LC_CTYPE", "LANG"}) {
        const char* value = std::getenv(var);
        if (value != nullptr && value[0] != '\0') {
            std::string lower(value);
            std::transform(
                lower.begin(), lower.end(), lower.begin(),
                [](unsigned char c) { return std::tolower(c); }
            );
            return lower.find("utf-8") != std::string::npos ||
                   lower.find("utf8") != std::string::npos;
        }
    }
    return false;
}

/* 0 means unlimited: stdout is not a terminal. */
size_t terminal_width() {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0) {
        return 0;
    }
    return ws.ws_col;
}

/* Splits UTF-8 text into code points; one code point is one column. */
std::vector<std::string> code_points(const std::string& s) {
    std::vector<std::string> out;
    for (size_t i = 0; i < s.size();) {
        unsigned char c = s[i];
        size_t len = 1;
        if (c >= 0xf0) {
            len = 4;
        } else if (c >= 0xe0) {
            len = 3;
        } else if (c >= 0xc0) {
            len = 2;
        }
        out.push_back(s.substr(i, len));
        i += len;
    }
    return out;
}

size_t display_width(const std::string& s) {
    return code_points(s).size();
}

bool breaks_after(const std::string& cp) {
    return cp == " " || cp == "," || cp == "/" || cp == ":" || cp == "-";
}

/* Wraps a cell to `width` columns: after a separator when one is close
 * enough to the edge, otherwise in the middle of a word. */
std::vector<std::string> wrap(const std::string& text, size_t width) {
    std::vector<std::string> lines;
    std::vector<std::string> cps = code_points(text);
    size_t start = 0;
    do {
        size_t remaining = cps.size() - start;
        size_t take = remaining;
        if (remaining > width) {
            take = width;
            for (size_t i = width; i > width / 2; --i) {
                if (breaks_after(cps[start + i - 1])) {
                    take = i;
                    break;
                }
            }
        }
        std::string line;
        for (size_t i = 0; i < take; ++i) {
            line += cps[start + i];
        }
        while (!line.empty() && line.back() == ' ') {
            line.pop_back();
        }
        lines.push_back(line);
        start += take;
    } while (start < cps.size());
    return lines;
}

std::string repeat(const char* glyph, size_t n) {
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        out += glyph;
    }
    return out;
}

struct Column {
    std::string name;
    RawstorCliColumnType type;
    size_t index;
};

std::vector<std::string> split_columns(const char* columns) {
    std::vector<std::string> out;
    std::stringstream ss(columns);
    std::string item;
    while (std::getline(ss, item, ',')) {
        out.push_back(item);
    }
    return out;
}

std::vector<Column> select_columns(
    const RawstorCliTable& table, const std::vector<std::string>& want
) {
    std::vector<Column> out;
    if (want.empty()) {
        for (size_t i = 0; i < table.names.size(); ++i) {
            out.push_back({table.names[i], table.types[i], i});
        }
        return out;
    }
    for (const std::string& name : want) {
        for (size_t i = 0; i < table.names.size(); ++i) {
            if (table.names[i] == name) {
                out.push_back({name, table.types[i], i});
                break;
            }
        }
    }
    return out;
}

void print_table(
    const RawstorCliTable& table, const std::vector<Column>& cols,
    bool header = true
) {
    const Glyphs& g = (isatty(STDOUT_FILENO) && locale_is_utf8())
                          ? unicode_glyphs
                          : ascii_glyphs;
    size_t n = cols.size();

    std::vector<std::string> headers;
    for (const Column& c : cols) {
        std::string h = c.name;
        std::transform(h.begin(), h.end(), h.begin(), [](unsigned char ch) {
            return std::toupper(ch);
        });
        headers.push_back(header ? h : "");
    }

    std::vector<size_t> widths(n);
    for (size_t c = 0; c < n; ++c) {
        widths[c] = display_width(headers[c]);
        for (const auto& row : table.texts) {
            widths[c] = std::max(widths[c], display_width(row[cols[c].index]));
        }
    }

    /* "│ a │ b │": a border before every column and one after the last, plus
     * a space of padding on both sides of every column. */
    size_t overhead = 3 * n + 1;
    size_t limit = terminal_width();
    if (limit > 0) {
        /* A header is never broken, and a long cell keeps enough width to
         * stay readable. A table that still does not fit overflows the
         * terminal instead of turning into confetti. */
        std::vector<size_t> min_widths(n);
        for (size_t c = 0; c < n; ++c) {
            min_widths[c] = std::max(
                display_width(headers[c]), std::min(widths[c], size_t(12))
            );
        }
        auto total = [&]() {
            size_t sum = overhead;
            for (size_t w : widths) {
                sum += w;
            }
            return sum;
        };
        /* Narrow the widest column first, so short columns keep their shape. */
        while (total() > limit) {
            bool found = false;
            size_t widest = 0;
            for (size_t c = 0; c < n; ++c) {
                if (widths[c] > min_widths[c] &&
                    (!found || widths[c] > widths[widest])) {
                    widest = c;
                    found = true;
                }
            }
            if (!found) {
                break;
            }
            --widths[widest];
        }
    }

    auto rule = [&](int kind) {
        std::string line = g.cross[kind][0];
        for (size_t c = 0; c < n; ++c) {
            line += repeat(g.horizontal, widths[c] + 2);
            line += g.cross[kind][c + 1 < n ? 1 : 2];
        }
        std::puts(line.c_str());
    };

    using Cells = std::vector<std::vector<std::string>>;
    auto print_row = [&](const Cells& cells, bool header) {
        size_t height = 1;
        for (const auto& lines : cells) {
            height = std::max(height, lines.size());
        }
        for (size_t l = 0; l < height; ++l) {
            std::string line = g.vertical;
            for (size_t c = 0; c < n; ++c) {
                const std::string text = l < cells[c].size() ? cells[c][l] : "";
                size_t pad =
                    widths[c] - std::min(widths[c], display_width(text));
                bool right =
                    !header && cols[c].type == RAWSTOR_CLI_COLUMN_NUMBER;
                line += " ";
                line += right ? std::string(pad, ' ') + text
                              : text + std::string(pad, ' ');
                line += " ";
                line += g.vertical;
            }
            std::puts(line.c_str());
        }
    };

    std::vector<Cells> body;
    bool wrapped = false;
    for (const auto& row : table.texts) {
        Cells cells;
        for (size_t c = 0; c < n; ++c) {
            cells.push_back(wrap(row[cols[c].index], widths[c]));
            wrapped = wrapped || cells.back().size() > 1;
        }
        body.push_back(cells);
    }

    Cells head;
    for (size_t c = 0; c < n; ++c) {
        head.push_back(wrap(headers[c], widths[c]));
    }

    rule(0);
    if (header) {
        print_row(head, true);
        rule(1);
    }
    for (size_t r = 0; r < body.size(); ++r) {
        /* Without separators a wrapped row would run into its neighbours. */
        if (wrapped && r > 0) {
            rule(1);
        }
        print_row(body[r], false);
    }
    rule(2);
}

/* A card as a key/value table: one row per selected column. */
void print_record(
    const RawstorCliTable& record, const std::vector<Column>& cols
) {
    RawstorCliTable kv;
    kv.names = {"key", "value"};
    kv.types = {RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING};
    for (const Column& c : cols) {
        kv.texts.push_back({c.name, record.texts[0][c.index]});
        kv.nulls.push_back({false, false});
        kv.numbers.push_back({0, 0});
    }
    print_table(kv, select_columns(kv, {}), false);
}

json table_json(const RawstorCliTable& table, const std::vector<Column>& cols) {
    json rows = json::array();
    for (size_t r = 0; r < table.texts.size(); ++r) {
        json row = json::object();
        for (const Column& c : cols) {
            if (table.nulls[r][c.index]) {
                row[c.name] = nullptr;
            } else if (c.type == RAWSTOR_CLI_COLUMN_NUMBER) {
                row[c.name] = (unsigned long long)table.numbers[r][c.index];
            } else {
                row[c.name] = table.texts[r][c.index];
            }
        }
        rows.push_back(row);
    }
    if (table.record) {
        return rows.empty() ? json::object() : rows[0];
    }
    return rows;
}

void print_values(
    const RawstorCliTable& table, const std::vector<Column>& cols
) {
    for (size_t r = 0; r < table.texts.size(); ++r) {
        std::string line;
        for (size_t c = 0; c < cols.size(); ++c) {
            if (c > 0) {
                line += '\t';
            }
            if (table.nulls[r][cols[c].index]) {
                continue;
            }
            if (cols[c].type == RAWSTOR_CLI_COLUMN_NUMBER) {
                line += std::to_string(
                    (unsigned long long)table.numbers[r][cols[c].index]
                );
            } else {
                line += table.texts[r][cols[c].index];
            }
        }
        std::puts(line.c_str());
    }
}

} // namespace

extern "C" {

void rawstor_cli_target_ids(
    const char* target, char* uuid, size_t uuid_size, char* version,
    size_t version_size
) {
    uuid[0] = '\0';
    version[0] = '\0';
    if (rawstor_target_id(target, uuid, uuid_size) < 0) {
        uuid[0] = '\0';
    }
    if (rawstor_target_version_id(target, version, version_size) < 0) {
        version[0] = '\0';
    }
}

int rawstor_cli_output_set_format(RawstorCliOutput* output, const char* name) {
    if (std::strcmp(name, "table") == 0) {
        output->format = RAWSTOR_CLI_FORMAT_TABLE;
    } else if (std::strcmp(name, "json") == 0) {
        output->format = RAWSTOR_CLI_FORMAT_JSON;
    } else if (std::strcmp(name, "value") == 0) {
        output->format = RAWSTOR_CLI_FORMAT_VALUE;
    } else {
        return -1;
    }
    return 0;
}

RawstorCliTable* rawstor_cli_record_create(
    const char* name, const char* const* names,
    const enum RawstorCliColumnType* types, size_t ncolumns
) {
    RawstorCliTable* table =
        rawstor_cli_table_create(name, names, types, ncolumns);
    if (table != nullptr) {
        table->record = true;
    }
    return table;
}

RawstorCliTable* rawstor_cli_table_create(
    const char* name, const char* const* names,
    const enum RawstorCliColumnType* types, size_t ncolumns
) {
    try {
        RawstorCliTable* table = new RawstorCliTable;
        table->name = name;
        table->names.assign(names, names + ncolumns);
        table->types.assign(types, types + ncolumns);
        return table;
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}

int rawstor_cli_table_add_row(
    RawstorCliTable* table, const RawstorCliCell* cells
) {
    try {
        std::vector<std::string> texts;
        std::vector<bool> nulls;
        std::vector<uint64_t> numbers;
        for (size_t i = 0; i < table->names.size(); ++i) {
            texts.push_back(cells[i].text != nullptr ? cells[i].text : "");
            nulls.push_back(cells[i].text == nullptr);
            numbers.push_back(cells[i].number);
        }
        table->texts.push_back(std::move(texts));
        table->nulls.push_back(std::move(nulls));
        table->numbers.push_back(std::move(numbers));
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

void rawstor_cli_table_delete(RawstorCliTable* table) {
    delete table;
}

int rawstor_cli_output_check(
    const RawstorCliOutput* output, RawstorCliTable* const* tables,
    size_t ntables
) {
    try {
        std::vector<std::string> want;
        if (output->columns != nullptr) {
            want = split_columns(output->columns);
        }

        for (const std::string& name : want) {
            bool known = false;
            for (size_t t = 0; t < ntables; ++t) {
                const auto& names = tables[t]->names;
                known = known || std::find(names.begin(), names.end(), name) !=
                                     names.end();
            }
            if (!known) {
                std::string valid;
                for (size_t t = 0; t < ntables; ++t) {
                    for (const std::string& n : tables[t]->names) {
                        valid += (valid.empty() ? "" : ", ") + n;
                    }
                }
                std::fprintf(
                    stderr, "Unknown column: %s (available: %s)\n",
                    name.c_str(), valid.c_str()
                );
                return EX_USAGE;
            }
        }

        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Output failed: %s\n", e.what());
        return EXIT_FAILURE;
    }
}

int rawstor_cli_output_print(
    const RawstorCliOutput* output, RawstorCliTable* const* tables,
    size_t ntables
) {
    try {
        std::vector<std::string> want;
        if (output->columns != nullptr) {
            want = split_columns(output->columns);
        }

        int checked = rawstor_cli_output_check(output, tables, ntables);
        if (checked != 0) {
            return checked;
        }

        json document = json::object();
        bool first = true;
        for (size_t t = 0; t < ntables; ++t) {
            std::vector<Column> cols = select_columns(*tables[t], want);
            if (cols.empty()) {
                continue;
            }
            switch (output->format) {
            case RAWSTOR_CLI_FORMAT_TABLE:
                if (!first) {
                    std::puts("");
                }
                if (tables[t]->record) {
                    print_record(*tables[t], cols);
                } else {
                    print_table(*tables[t], cols);
                }
                break;
            case RAWSTOR_CLI_FORMAT_VALUE:
                print_values(*tables[t], cols);
                break;
            case RAWSTOR_CLI_FORMAT_JSON:
                if (ntables == 1) {
                    document = table_json(*tables[t], cols);
                } else if (tables[t]->record) {
                    json fields = table_json(*tables[t], cols);
                    for (auto& field : fields.items()) {
                        document[field.key()] = field.value();
                    }
                } else {
                    document[tables[t]->name] = table_json(*tables[t], cols);
                }
                break;
            }
            first = false;
        }
        if (output->format == RAWSTOR_CLI_FORMAT_JSON) {
            std::puts(document.dump(2).c_str());
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Output failed: %s\n", e.what());
        return EXIT_FAILURE;
    }
}

} // extern "C"
