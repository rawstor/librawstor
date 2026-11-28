#include "sqlite_database.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <sqlite3.h>

#include <memory>
#include <string>
#include <vector>

#include <cerrno>

namespace {

[[noreturn]] void throw_sqlite(sqlite3* db, const char* what) {
    rawstd_error("%s: %s\n", what, sqlite3_errmsg(db));
    RAWSTD_THROW_SYSTEM_ERROR(EIO);
}

} // namespace

namespace rawstor {
namespace mdsserver {
namespace db {

SqliteStatement::SqliteStatement(sqlite3* db, const char* sql) :
    _db(db),
    _stmt(nullptr) {
    if (sqlite3_prepare_v2(db, sql, -1, &_stmt, nullptr) != SQLITE_OK) {
        throw_sqlite(db, "sqlite prepare");
    }
}

SqliteStatement::~SqliteStatement() {
    sqlite3_finalize(_stmt);
}

Statement& SqliteStatement::bind_blob(int pos, const void* data, size_t size) {
    // A null pointer would bind NULL, not an empty blob.
    if (size == 0) {
        data = "";
    }
    if (sqlite3_bind_blob(_stmt, pos, data, size, SQLITE_STATIC) != SQLITE_OK) {
        throw_sqlite(_db, "sqlite bind");
    }
    return *this;
}

Statement& SqliteStatement::bind_int64(int pos, uint64_t value) {
    if (sqlite3_bind_int64(_stmt, pos, static_cast<sqlite3_int64>(value)) !=
        SQLITE_OK) {
        throw_sqlite(_db, "sqlite bind");
    }
    return *this;
}

Statement& SqliteStatement::bind_text(int pos, const std::string& value) {
    if (sqlite3_bind_text(_stmt, pos, value.c_str(), -1, SQLITE_TRANSIENT) !=
        SQLITE_OK) {
        throw_sqlite(_db, "sqlite bind");
    }
    return *this;
}

void SqliteStatement::reset() {
    if (sqlite3_reset(_stmt) != SQLITE_OK) {
        throw_sqlite(_db, "sqlite reset");
    }
}

bool SqliteStatement::step() {
    int res = sqlite3_step(_stmt);
    if (res == SQLITE_ROW) {
        return true;
    }
    if (res == SQLITE_DONE) {
        return false;
    }
    if (res == SQLITE_CONSTRAINT) {
        RAWSTD_THROW_SYSTEM_ERROR(EEXIST);
    }
    throw_sqlite(_db, "sqlite step");
}

uint64_t SqliteStatement::column_int64(int pos) {
    return static_cast<uint64_t>(sqlite3_column_int64(_stmt, pos));
}

std::string SqliteStatement::column_text(int pos) {
    const unsigned char* text = sqlite3_column_text(_stmt, pos);
    return text == nullptr ? std::string()
                           : std::string(reinterpret_cast<const char*>(text));
}

std::vector<unsigned char> SqliteStatement::column_blob(int pos) {
    const unsigned char* data =
        static_cast<const unsigned char*>(sqlite3_column_blob(_stmt, pos));
    int size = sqlite3_column_bytes(_stmt, pos);
    return std::vector<unsigned char>(data, data + size);
}

SqliteDatabase::SqliteDatabase(const std::string& path) : _db(nullptr) {
    int res = sqlite3_open_v2(
        path.c_str(), &_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX,
        nullptr
    );
    if (res != SQLITE_OK) {
        rawstd_error(
            "Failed to open MDS store %s: %s\n", path.c_str(),
            _db != nullptr ? sqlite3_errmsg(_db) : "?"
        );
        sqlite3_close(_db);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    try {
        /*
         * WAL + synchronous=FULL: every committed mutation is durable —
         * required for witness votes and object-map mutations.
         */
        exec("PRAGMA journal_mode=WAL;");
        exec("PRAGMA synchronous=FULL;");
        exec("PRAGMA foreign_keys=ON;");
    } catch (...) {
        sqlite3_close(_db);
        throw;
    }
}

SqliteDatabase::~SqliteDatabase() {
    sqlite3_close(_db);
}

void SqliteDatabase::exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(_db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        rawstd_error("sqlite exec: %s\n", err != nullptr ? err : "?");
        sqlite3_free(err);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

std::unique_ptr<Statement> SqliteDatabase::prepare(const char* sql) {
    return std::make_unique<SqliteStatement>(_db, sql);
}

void SqliteDatabase::begin(TransactionMode mode) {
    exec(mode == TransactionMode::write ? "BEGIN IMMEDIATE;" : "BEGIN;");
}

void SqliteDatabase::commit() {
    exec("COMMIT;");
}

void SqliteDatabase::rollback() noexcept {
    sqlite3_exec(_db, "ROLLBACK;", nullptr, nullptr, nullptr);
}

uint64_t SqliteDatabase::changes() {
    return static_cast<uint64_t>(sqlite3_changes(_db));
}

uint64_t SqliteDatabase::schema_version() {
    SqliteStatement version(_db, "PRAGMA user_version;");
    if (!version.step()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    return version.column_int64(0);
}

void SqliteDatabase::set_schema_version(uint64_t version) {
    // PRAGMA takes no parameters.
    exec(("PRAGMA user_version=" + std::to_string(version) + ";").c_str());
}

bool SqliteDatabase::has_table(const char* name) {
    SqliteStatement tables(
        _db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
             "name=?;"
    );
    tables.bind_text(1, name);
    if (!tables.step()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    return tables.column_int64(0) != 0;
}

} // namespace db
} // namespace mdsserver
} // namespace rawstor
