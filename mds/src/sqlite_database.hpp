#ifndef RAWSTOR_MDS_SQLITE_DATABASE_HPP
#define RAWSTOR_MDS_SQLITE_DATABASE_HPP

#include "database.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct sqlite3;
struct sqlite3_stmt;

namespace rawstor {
namespace mdsserver {
namespace db {

class SqliteStatement final : public Statement {
private:
    sqlite3* _db;
    sqlite3_stmt* _stmt;

public:
    SqliteStatement(sqlite3* db, const char* sql);
    ~SqliteStatement() override;

    Statement& bind_blob(int pos, const void* data, size_t size) override;
    Statement& bind_int64(int pos, uint64_t value) override;
    Statement& bind_text(int pos, const std::string& value) override;

    void reset() override;
    bool step() override;

    uint64_t column_int64(int pos) override;
    std::string column_text(int pos) override;
    std::vector<unsigned char> column_blob(int pos) override;
};

/*
 * An SQLite file: WAL journal, synchronous=FULL and foreign keys enforced.
 * The schema version is the file's user_version.
 */
class SqliteDatabase final : public Database {
private:
    sqlite3* _db;

public:
    explicit SqliteDatabase(const std::string& path);
    ~SqliteDatabase() override;

    void exec(const char* sql) override;
    std::unique_ptr<Statement> prepare(const char* sql) override;

    void begin(TransactionMode mode) override;
    void commit() override;
    void rollback() noexcept override;

    uint64_t changes() override;

    uint64_t schema_version() override;
    void set_schema_version(uint64_t version) override;

    bool has_table(const char* name) override;
};

} // namespace db
} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_SQLITE_DATABASE_HPP
