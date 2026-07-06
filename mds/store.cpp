#include "store.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <sqlite3.h>

#include <utility>

#include <cerrno>
#include <cstring>
#include <ctime>

namespace {

using rawstor::mds::PlacementPolicy;

constexpr const char* SCHEMA =
    "CREATE TABLE IF NOT EXISTS volumes ("
    "  volume_id BLOB PRIMARY KEY,"
    "  logical_size INTEGER NOT NULL,"
    "  chunk_size INTEGER NOT NULL,"
    "  width INTEGER NOT NULL,"
    "  failure_domain INTEGER NOT NULL,"
    "  stripe_width INTEGER NOT NULL,"
    "  placement_seed INTEGER NOT NULL,"
    "  map_epoch INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS chunk_map ("
    "  volume_id BLOB NOT NULL"
    "    REFERENCES volumes(volume_id) ON DELETE CASCADE,"
    "  logical_index INTEGER NOT NULL,"
    "  slot_index INTEGER NOT NULL,"
    "  ost_id BLOB NOT NULL,"
    "  PRIMARY KEY (volume_id, logical_index, slot_index)"
    ") WITHOUT ROWID;";

[[noreturn]] void throw_sqlite(sqlite3* db, const char* what) {
    rawstd_error("%s: %s\n", what, sqlite3_errmsg(db));
    RAWSTD_THROW_SYSTEM_ERROR(EIO);
}

void exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        rawstd_error("sqlite exec: %s\n", err != nullptr ? err : "?");
        sqlite3_free(err);
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

/* RAII prepared statement. */
class Stmt final {
private:
    sqlite3* _db;
    sqlite3_stmt* _stmt;

public:
    Stmt(sqlite3* db, const char* sql) : _db(db), _stmt(nullptr) {
        if (sqlite3_prepare_v2(db, sql, -1, &_stmt, nullptr) != SQLITE_OK) {
            throw_sqlite(db, "sqlite prepare");
        }
    }
    Stmt(const Stmt&) = delete;
    ~Stmt() { sqlite3_finalize(_stmt); }

    Stmt& operator=(const Stmt&) = delete;

    Stmt& bind_blob(int pos, const void* data, size_t size) {
        if (sqlite3_bind_blob(_stmt, pos, data, size, SQLITE_STATIC) !=
            SQLITE_OK) {
            throw_sqlite(_db, "sqlite bind");
        }
        return *this;
    }

    Stmt& bind_int64(int pos, uint64_t value) {
        if (sqlite3_bind_int64(_stmt, pos, static_cast<sqlite3_int64>(value)) !=
            SQLITE_OK) {
            throw_sqlite(_db, "sqlite bind");
        }
        return *this;
    }

    void reset() {
        if (sqlite3_reset(_stmt) != SQLITE_OK) {
            throw_sqlite(_db, "sqlite reset");
        }
    }

    /* True on a row, false on done. */
    bool step() {
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

    uint64_t column_int64(int pos) {
        return static_cast<uint64_t>(sqlite3_column_int64(_stmt, pos));
    }

    void column_uuid(int pos, RawstdUUID* out) {
        if (sqlite3_column_bytes(_stmt, pos) !=
            static_cast<int>(sizeof(out->bytes))) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        memcpy(out->bytes, sqlite3_column_blob(_stmt, pos), sizeof(out->bytes));
    }
};

/* Scoped transaction: rolls back unless committed. */
class Transaction final {
private:
    sqlite3* _db;
    bool _committed;

public:
    explicit Transaction(sqlite3* db) : _db(db), _committed(false) {
        exec(_db, "BEGIN IMMEDIATE;");
    }
    Transaction(const Transaction&) = delete;
    ~Transaction() {
        if (!_committed) {
            sqlite3_exec(_db, "ROLLBACK;", nullptr, nullptr, nullptr);
        }
    }

    Transaction& operator=(const Transaction&) = delete;

    void commit() {
        exec(_db, "COMMIT;");
        _committed = true;
    }
};

uint64_t nchunks_of(uint64_t logical_size, uint64_t chunk_size) {
    return (logical_size + chunk_size - 1) / chunk_size;
}

void validate_geometry(uint64_t logical_size, uint64_t chunk_size) {
    if (logical_size == 0) {
        rawstd_error("Volume size 0\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    /* Architecture.md: the chunk size must be a power of two. */
    if (chunk_size == 0 || (chunk_size & (chunk_size - 1)) != 0) {
        rawstd_error("Chunk size is not a power of two\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (nchunks_of(logical_size, chunk_size) > UINT32_MAX) {
        rawstd_error("Volume has too many chunks\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
}

void insert_chunks(
    sqlite3* db, const rawstor::mds::Topology& topology,
    const RawstdUUID& volume_id, uint64_t first_index, uint64_t end_index,
    uint64_t chunk_size, const PlacementPolicy& policy
) {
    (void)chunk_size;
    Stmt insert(
        db, "INSERT INTO chunk_map"
            " (volume_id, logical_index, slot_index, ost_id)"
            " VALUES (?, ?, ?, ?);"
    );

    for (uint64_t index = first_index; index < end_index; ++index) {
        std::vector<rawstor::mds::PlacementSlot> slots =
            rawstor::mds::place(topology, volume_id, index, policy);
        for (const rawstor::mds::PlacementSlot& slot : slots) {
            insert.reset();
            insert.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
                .bind_int64(2, index)
                .bind_int64(3, slot.slot_index)
                .bind_blob(4, slot.ost_id.bytes, sizeof(slot.ost_id.bytes))
                .step();
        }
    }
}

} // namespace

namespace rawstor {
namespace mds {

VolumeStore::VolumeStore(const std::string& path, Topology topology) :
    _db(nullptr),
    _topology(std::move(topology)) {
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
         * non-negotiable once witness records live here (stage 3).
         */
        exec(_db, "PRAGMA journal_mode=WAL;");
        exec(_db, "PRAGMA synchronous=FULL;");
        exec(_db, "PRAGMA foreign_keys=ON;");
        exec(_db, SCHEMA);
    } catch (...) {
        sqlite3_close(_db);
        throw;
    }
}

VolumeStore::~VolumeStore() {
    sqlite3_close(_db);
}

VolumeDescriptor VolumeStore::_descriptor(const RawstdUUID& volume_id) {
    Stmt select(
        _db, "SELECT logical_size, chunk_size, width, failure_domain,"
             " stripe_width, placement_seed, map_epoch"
             " FROM volumes WHERE volume_id = ?;"
    );
    select.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes));

    if (!select.step()) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    VolumeDescriptor ret{};
    ret.volume_id = volume_id;
    ret.logical_size = select.column_int64(0);
    ret.chunk_size = select.column_int64(1);
    ret.policy.width = static_cast<unsigned>(select.column_int64(2));
    ret.policy.failure_domain = static_cast<Level>(select.column_int64(3));
    ret.policy.stripe_width = select.column_int64(4);
    ret.policy.seed = select.column_int64(5);
    ret.map_epoch = select.column_int64(6);
    return ret;
}

VolumeDescriptor VolumeStore::create(
    const RawstdUUID& volume_id, uint64_t logical_size, uint64_t chunk_size,
    const PlacementPolicy& policy
) {
    validate_geometry(logical_size, chunk_size);

    VolumeDescriptor ret{};
    ret.volume_id = volume_id;
    ret.logical_size = logical_size;
    ret.chunk_size = chunk_size;
    ret.policy = policy;
    ret.map_epoch = 1;

    uint64_t nchunks = nchunks_of(logical_size, chunk_size);

    /* Hard-fails on an unsatisfiable topology before anything lands. */
    place(_topology, ret.volume_id, 0, policy);

    Transaction tx(_db);

    {
        Stmt insert(
            _db, "INSERT INTO volumes"
                 " (volume_id, logical_size, chunk_size, width,"
                 " failure_domain, stripe_width, placement_seed, map_epoch,"
                 " created_at)"
                 " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"
        );
        insert.bind_blob(1, ret.volume_id.bytes, sizeof(ret.volume_id.bytes))
            .bind_int64(2, logical_size)
            .bind_int64(3, chunk_size)
            .bind_int64(4, policy.width)
            .bind_int64(5, static_cast<uint64_t>(policy.failure_domain))
            .bind_int64(6, policy.stripe_width)
            .bind_int64(7, policy.seed)
            .bind_int64(8, ret.map_epoch)
            .bind_int64(9, static_cast<uint64_t>(time(nullptr)))
            .step();
    }

    insert_chunks(
        _db, _topology, ret.volume_id, 0, nchunks, chunk_size, ret.policy
    );

    tx.commit();

    return ret;
}

VolumeMap VolumeStore::open(const RawstdUUID& volume_id, uint64_t snap_id) {
    if (snap_id != 0) {
        /* Snapshots are stage 2. */
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    VolumeMap ret{};
    ret.descriptor = _descriptor(volume_id);

    uint64_t nchunks =
        nchunks_of(ret.descriptor.logical_size, ret.descriptor.chunk_size);
    ret.chunks.resize(nchunks);

    Stmt select(
        _db, "SELECT logical_index, slot_index, ost_id FROM chunk_map"
             " WHERE volume_id = ?"
             " ORDER BY logical_index, slot_index;"
    );
    select.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes));

    while (select.step()) {
        uint64_t index = select.column_int64(0);
        if (index >= nchunks) {
            rawstd_error("MDS store: chunk index out of volume bounds\n");
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        PlacementSlot slot{};
        slot.slot_index = static_cast<uint8_t>(select.column_int64(1));
        select.column_uuid(2, &slot.ost_id);
        ret.chunks[index].push_back(slot);
    }

    for (const std::vector<PlacementSlot>& slots : ret.chunks) {
        if (slots.size() != ret.descriptor.policy.width) {
            rawstd_error("MDS store: chunk map is missing slots\n");
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
    }

    return ret;
}

uint64_t VolumeStore::resize(const RawstdUUID& volume_id, uint64_t new_size) {
    VolumeDescriptor descriptor = _descriptor(volume_id);

    validate_geometry(new_size, descriptor.chunk_size);

    /* Grow-only in v1: shrink interacts with GC and snapshots. */
    if (new_size < descriptor.logical_size) {
        rawstd_error("Volume shrink is not supported\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    uint64_t old_chunks =
        nchunks_of(descriptor.logical_size, descriptor.chunk_size);
    uint64_t new_chunks = nchunks_of(new_size, descriptor.chunk_size);
    uint64_t map_epoch = descriptor.map_epoch + 1;

    Transaction tx(_db);

    {
        Stmt update(
            _db, "UPDATE volumes SET logical_size = ?, map_epoch = ?"
                 " WHERE volume_id = ?;"
        );
        update.bind_int64(1, new_size)
            .bind_int64(2, map_epoch)
            .bind_blob(3, volume_id.bytes, sizeof(volume_id.bytes))
            .step();
    }

    insert_chunks(
        _db, _topology, volume_id, old_chunks, new_chunks,
        descriptor.chunk_size, descriptor.policy
    );

    tx.commit();

    return map_epoch;
}

void VolumeStore::remove(const RawstdUUID& volume_id) {
    Transaction tx(_db);

    {
        Stmt del(_db, "DELETE FROM volumes WHERE volume_id = ?;");
        del.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes)).step();
    }

    if (sqlite3_changes(_db) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    tx.commit();
}

} // namespace mds
} // namespace rawstor
