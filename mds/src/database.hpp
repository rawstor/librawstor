#ifndef RAWSTOR_MDS_DATABASE_HPP
#define RAWSTOR_MDS_DATABASE_HPP

#include <rawstd/uuid.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace rawstor {
namespace mdsserver {
namespace db {

/*
 * A prepared statement. Parameters are numbered from 1, columns from 0.
 *
 * Errors are thrown as std::system_error: EEXIST for a statement that
 * violates a constraint, EAGAIN for database write contention, and EIO
 * for other database failures.
 */
class Statement {
public:
    Statement() = default;
    Statement(const Statement&) = delete;
    Statement(Statement&&) = delete;
    virtual ~Statement() = default;

    Statement& operator=(const Statement&) = delete;
    Statement& operator=(Statement&&) = delete;

    // A blob is not copied: `data` must stay valid until the statement is
    // reset or destroyed. Text is copied.
    virtual Statement& bind_blob(int pos, const void* data, size_t size) = 0;
    virtual Statement& bind_int64(int pos, uint64_t value) = 0;
    virtual Statement& bind_text(int pos, const std::string& value) = 0;

    // Rewinds the statement to run it again; the bindings stay.
    virtual void reset() = 0;

    // True on a row, false on done.
    virtual bool step() = 0;

    virtual uint64_t column_int64(int pos) = 0;
    virtual std::string column_text(int pos) = 0;
    virtual std::vector<unsigned char> column_blob(int pos) = 0;

    // EIO unless the column is a blob of exactly a UUID's size.
    void column_uuid(int pos, RawstdUUID* out);
};

enum class TransactionMode { read, write };

/*
 * One connection to the database the MDS store keeps its map in. It is not
 * thread-safe: the caller serializes every call on it.
 *
 * A committed transaction is durable before commit() returns.
 *
 * Errors are thrown as std::system_error like Statement's.
 */
class Database {
public:
    /*
     * Opens the database a connection string names, creating it if missing.
     * The scheme picks the database: `sqlite:///path/to/file` is an SQLite
     * file. EINVAL for a malformed connection string or another scheme.
     */
    static std::unique_ptr<Database> open(const std::string& uri);

    /* EINVAL unless open() takes the connection string; opens nothing. */
    static void validate(const std::string& uri);

    Database() = default;
    Database(const Database&) = delete;
    Database(Database&&) = delete;
    virtual ~Database() = default;

    Database& operator=(const Database&) = delete;
    Database& operator=(Database&&) = delete;

    // Runs one or more statements that take no parameters and return no
    // rows.
    virtual void exec(const char* sql) = 0;

    virtual std::unique_ptr<Statement> prepare(const char* sql) = 0;

    // A write transaction reserves the write lock before reading state.
    virtual void begin(TransactionMode mode) = 0;
    virtual void commit() = 0;
    virtual void rollback() noexcept = 0;

    // Rows inserted, updated or deleted by the last statement that ran.
    virtual uint64_t changes() = 0;

    // The layout version the store recorded; 0 for none.
    virtual uint64_t schema_version() = 0;
    virtual void set_schema_version(uint64_t version) = 0;

    virtual bool has_table(const char* name) = 0;
};

/* Scoped transaction: rolls back unless committed. */
class Transaction final {
private:
    Database& _db;
    bool _committed;

public:
    explicit Transaction(
        Database& db, TransactionMode mode = TransactionMode::write
    );
    Transaction(const Transaction&) = delete;
    Transaction(Transaction&&) = delete;
    ~Transaction();

    Transaction& operator=(const Transaction&) = delete;
    Transaction& operator=(Transaction&&) = delete;

    void commit();
};

} // namespace db
} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_DATABASE_HPP
