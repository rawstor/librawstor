#include "store.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <map>
#include <string>
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
    "  created_at INTEGER NOT NULL,"
    "  next_snap_id INTEGER NOT NULL DEFAULT 1"
    ");"
    "CREATE TABLE IF NOT EXISTS chunk_map ("
    "  volume_id BLOB NOT NULL"
    "    REFERENCES volumes(volume_id) ON DELETE CASCADE,"
    "  logical_index INTEGER NOT NULL,"
    "  slot_index INTEGER NOT NULL,"
    "  ost_id BLOB NOT NULL,"
    "  PRIMARY KEY (volume_id, logical_index, slot_index)"
    ") WITHOUT ROWID;"
    /*
     * No ON DELETE CASCADE from volumes: a volume with snapshots must
     * not silently disappear — remove() refuses with EBUSY.
     */
    "CREATE TABLE IF NOT EXISTS snapshots ("
    "  volume_id BLOB NOT NULL REFERENCES volumes(volume_id),"
    "  snap_id INTEGER NOT NULL,"
    "  logical_size INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  PRIMARY KEY (volume_id, snap_id)"
    ") WITHOUT ROWID;"
    "CREATE TABLE IF NOT EXISTS snapshot_members ("
    "  volume_id BLOB NOT NULL,"
    "  snap_id INTEGER NOT NULL,"
    "  logical_index INTEGER NOT NULL,"
    "  ost_id BLOB NOT NULL,"
    "  PRIMARY KEY (volume_id, snap_id, logical_index, ost_id),"
    "  FOREIGN KEY (volume_id, snap_id)"
    "    REFERENCES snapshots(volume_id, snap_id) ON DELETE CASCADE"
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

        /*
         * A pre-snapshot database has a volumes table without
         * next_snap_id (CREATE IF NOT EXISTS keeps it as is): the column
         * itself is the version marker.
         */
        sqlite3_stmt* probe = nullptr;
        if (sqlite3_prepare_v2(
                _db, "SELECT next_snap_id FROM volumes LIMIT 1;", -1, &probe,
                nullptr
            ) != SQLITE_OK) {
            exec(
                _db, "ALTER TABLE volumes"
                     " ADD COLUMN next_snap_id INTEGER NOT NULL DEFAULT 1;"
            );
        }
        sqlite3_finalize(probe);
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
        return _open_snapshot(volume_id, snap_id);
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

    /*
     * A chunk with no slots at all is unroutable: hard error. Fewer slots
     * than the policy width is a degraded but usable map (a reconstruct
     * scan that could not find every copy); the mirror layer handles the
     * reduced redundancy.
     */
    for (size_t index = 0; index < ret.chunks.size(); ++index) {
        if (ret.chunks[index].empty()) {
            rawstd_error("MDS store: chunk map is missing a chunk\n");
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        if (ret.chunks[index].size() != ret.descriptor.policy.width) {
            rawstd_warning(
                "MDS store: chunk %zu has %zu of %u slots\n", index,
                ret.chunks[index].size(), ret.descriptor.policy.width
            );
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

void VolumeStore::reconstruct(const std::vector<ScanRecord>& records) {
    struct Chunk {
        uint64_t size;
        /* Scan order becomes the slot order. */
        std::vector<RawstdUUID> ost_ids;
    };
    struct Volume {
        uint64_t chunk_size;
        unsigned width;
        std::map<uint64_t, Chunk> chunks;
        /* snap_id -> its own chunk set (taken before a resize = smaller). */
        std::map<uint64_t, std::map<uint64_t, Chunk>> snaps;
    };

    std::map<std::string, Volume> volumes;

    for (const ScanRecord& r : records) {
        /* Witness records are metadata-only votes, not data slots. */
        if (r.meta.member_kind != RAWSTOR_MEMBER_DATA) {
            continue;
        }

        static const uint8_t null_id[16] = {};
        if (memcmp(r.meta.volume_id, null_id, sizeof(null_id)) == 0) {
            /* A standalone object, not a volume chunk. */
            continue;
        }

        RawstdUUIDString obj_str;
        rawstd_uuid_to_string(&r.obj_id, &obj_str);

        std::string key(
            reinterpret_cast<const char*>(r.meta.volume_id),
            sizeof(r.meta.volume_id)
        );

        auto [it, fresh] = volumes.try_emplace(key);
        Volume& v = it->second;
        if (fresh) {
            v.chunk_size = r.meta.chunk_size;
            v.width = r.meta.width;
        } else if (v.chunk_size != r.meta.chunk_size ||
                   v.width != r.meta.width) {
            rawstd_error(
                "reconstruct: %s: identity conflicts with its volume\n",
                obj_str
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        auto [cit, chunk_fresh] =
            r.meta.snap_version == 0
                ? v.chunks.try_emplace(r.meta.logical_index)
                : v.snaps[r.meta.snap_version].try_emplace(
                      r.meta.logical_index
                  );
        Chunk& c = cit->second;

        bool duplicate = false;
        for (const RawstdUUID& ost : c.ost_ids) {
            if (memcmp(ost.bytes, r.ost_id.bytes, sizeof(ost.bytes)) == 0) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            rawstd_warning(
                "reconstruct: %s: duplicate record skipped\n", obj_str
            );
            continue;
        }

        c.ost_ids.push_back(r.ost_id);
        /*
         * Copies may disagree on size: a block backend rounds the device
         * up (LVM to the extent, ZFS to the volblocksize). The smallest
         * copy is the closest bound on what was requested.
         */
        c.size = chunk_fresh ? r.meta.size : std::min(c.size, r.meta.size);
    }

    Transaction tx(_db);

    exec(
        _db, "DELETE FROM snapshot_members;"
             "DELETE FROM snapshots;"
             "DELETE FROM volumes;"
    );

    for (const auto& [key, v] : volumes) {
        RawstdUUID volume_id;
        memcpy(volume_id.bytes, key.data(), sizeof(volume_id.bytes));
        RawstdUUIDString vol_str;
        rawstd_uuid_to_string(&volume_id, &vol_str);

        if (v.chunk_size == 0 || (v.chunk_size & (v.chunk_size - 1)) != 0 ||
            v.width == 0) {
            rawstd_error(
                "reconstruct: %s: malformed stored identity\n", vol_str
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        if (v.chunks.empty()) {
            /* Snapshot leftovers of a volume whose live data is gone. */
            rawstd_warning(
                "reconstruct: %s: only snapshot records survive, skipped\n",
                vol_str
            );
            continue;
        }

        /* std::map is ordered: the last key is the highest index. */
        uint64_t max_index = v.chunks.rbegin()->first;
        if (v.chunks.size() != max_index + 1) {
            rawstd_error(
                "reconstruct: %s: no surviving copy of %llu of %llu "
                "chunks\n",
                vol_str,
                static_cast<unsigned long long>(
                    max_index + 1 - v.chunks.size()
                ),
                static_cast<unsigned long long>(max_index + 1)
            );
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        /*
         * The tail chunk copy may be rounded up by its backend; clamping
         * keeps the chunk count consistent with the geometry. The
         * reconstructed size never shrinks below what was written.
         */
        uint64_t tail = std::min(v.chunks.rbegin()->second.size, v.chunk_size);
        if (tail == 0) {
            rawstd_error("reconstruct: %s: zero-sized tail chunk\n", vol_str);
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        uint64_t logical_size = max_index * v.chunk_size + tail;

        /*
         * Every version ever seen fences the reservation counter — a
         * leftover of a crashed snapshot attempt must not alias a later
         * snapshot under a reused id, so it counts even when it is not
         * registered below.
         */
        uint64_t next_snap_id =
            v.snaps.empty() ? 1 : v.snaps.rbegin()->first + 1;

        /*
         * The policy knobs are not persisted on chunks: existing chunks
         * keep their placement (the map below is explicit), the rebuilt
         * descriptor constrains only future resizes — weakest domain, so
         * a reduced post-disaster topology never fails validation.
         */
        {
            Stmt insert(
                _db, "INSERT INTO volumes"
                     " (volume_id, logical_size, chunk_size, width,"
                     " failure_domain, stripe_width, placement_seed,"
                     " map_epoch, created_at, next_snap_id)"
                     " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
            );
            insert.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
                .bind_int64(2, logical_size)
                .bind_int64(3, v.chunk_size)
                .bind_int64(4, v.width)
                .bind_int64(
                    5, static_cast<uint64_t>(rawstor::mds::Level::OST)
                )
                .bind_int64(6, STRIPE_ALL)
                .bind_int64(7, 0)
                .bind_int64(8, 1)
                .bind_int64(9, static_cast<uint64_t>(time(nullptr)))
                .bind_int64(10, next_snap_id)
                .step();
        }

        {
            Stmt insert(
                _db, "INSERT INTO chunk_map"
                     " (volume_id, logical_index, slot_index, ost_id)"
                     " VALUES (?, ?, ?, ?);"
            );
            for (const auto& [index, chunk] : v.chunks) {
                for (size_t slot = 0; slot < chunk.ost_ids.size(); ++slot) {
                    insert.reset();
                    insert
                        .bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
                        .bind_int64(2, index)
                        .bind_int64(3, slot)
                        .bind_blob(
                            4, chunk.ost_ids[slot].bytes,
                            sizeof(chunk.ost_ids[slot].bytes)
                        )
                        .step();
                }
            }
        }

        /*
         * Snapshot views: a version that covers every one of its chunks
         * is registered — a complete-but-uncommitted leftover is
         * indistinguishable from a committed snapshot and just as
         * consistent (drain + FLUSH preceded its CoWs). A version with a
         * hole is the leftover of a crashed attempt: garbage, left for
         * collection, never registered.
         */
        for (const auto& [snap_id, snap_chunks] : v.snaps) {
            uint64_t snap_max = snap_chunks.rbegin()->first;
            uint64_t snap_tail =
                std::min(snap_chunks.rbegin()->second.size, v.chunk_size);
            if (snap_chunks.size() != snap_max + 1 || snap_tail == 0) {
                rawstd_warning(
                    "reconstruct: %s@%llu: incomplete snapshot leftover, "
                    "not registered\n",
                    vol_str, static_cast<unsigned long long>(snap_id)
                );
                continue;
            }

            {
                Stmt insert(
                    _db, "INSERT INTO snapshots"
                         " (volume_id, snap_id, logical_size, created_at)"
                         " VALUES (?, ?, ?, ?);"
                );
                insert.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
                    .bind_int64(2, snap_id)
                    .bind_int64(3, snap_max * v.chunk_size + snap_tail)
                    .bind_int64(4, static_cast<uint64_t>(time(nullptr)))
                    .step();
            }

            Stmt insert(
                _db, "INSERT INTO snapshot_members"
                     " (volume_id, snap_id, logical_index, ost_id)"
                     " VALUES (?, ?, ?, ?);"
            );
            for (const auto& [index, chunk] : snap_chunks) {
                for (const RawstdUUID& ost : chunk.ost_ids) {
                    insert.reset();
                    insert
                        .bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
                        .bind_int64(2, snap_id)
                        .bind_int64(3, index)
                        .bind_blob(4, ost.bytes, sizeof(ost.bytes))
                        .step();
                }
            }
        }
    }

    tx.commit();

    rawstd_info(
        "reconstruct: %zu volumes rebuilt from %zu records\n", volumes.size(),
        records.size()
    );
}

void VolumeStore::remove(const RawstdUUID& volume_id) {
    Transaction tx(_db);

    {
        /* A volume with snapshots must not silently disappear. */
        Stmt busy(
            _db, "SELECT snap_id FROM snapshots WHERE volume_id = ? LIMIT 1;"
        );
        busy.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes));
        if (busy.step()) {
            rawstd_error("Volume has snapshots; remove them first\n");
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }
    }

    {
        Stmt del(_db, "DELETE FROM volumes WHERE volume_id = ?;");
        del.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes)).step();
    }

    if (sqlite3_changes(_db) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    tx.commit();
}

VolumeMap
VolumeStore::_open_snapshot(const RawstdUUID& volume_id, uint64_t snap_id) {
    VolumeMap ret{};
    ret.descriptor = _descriptor(volume_id);

    {
        Stmt select(
            _db, "SELECT logical_size FROM snapshots"
                 " WHERE volume_id = ? AND snap_id = ?;"
        );
        select.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
            .bind_int64(2, snap_id);
        if (!select.step()) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
        }
        /* The size the volume had when the snapshot was taken. */
        ret.descriptor.logical_size = select.column_int64(0);
    }

    uint64_t nchunks =
        nchunks_of(ret.descriptor.logical_size, ret.descriptor.chunk_size);
    ret.chunks.resize(nchunks);

    Stmt select(
        _db, "SELECT logical_index, ost_id FROM snapshot_members"
             " WHERE volume_id = ? AND snap_id = ?"
             " ORDER BY logical_index, ost_id;"
    );
    select.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
        .bind_int64(2, snap_id);

    uint64_t prev_index = 0;
    uint8_t slot = 0;
    while (select.step()) {
        uint64_t index = select.column_int64(0);
        if (index >= nchunks) {
            rawstd_error("MDS store: snapshot member out of bounds\n");
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        if (index != prev_index) {
            prev_index = index;
            slot = 0;
        }
        PlacementSlot member{};
        member.slot_index = slot++;
        select.column_uuid(1, &member.ost_id);
        ret.chunks[index].push_back(member);
    }

    /* snap_commit() never registers a snapshot with an uncovered chunk. */
    for (size_t index = 0; index < ret.chunks.size(); ++index) {
        if (ret.chunks[index].empty()) {
            rawstd_error("MDS store: snapshot is missing a chunk\n");
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
    }

    return ret;
}

uint64_t VolumeStore::snap_begin(const RawstdUUID& volume_id) {
    Transaction tx(_db);

    uint64_t snap_id;
    {
        Stmt select(
            _db, "SELECT next_snap_id FROM volumes WHERE volume_id = ?;"
        );
        select.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes));
        if (!select.step()) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
        }
        snap_id = select.column_int64(0);
    }

    {
        Stmt update(
            _db, "UPDATE volumes SET next_snap_id = ? WHERE volume_id = ?;"
        );
        update.bind_int64(1, snap_id + 1)
            .bind_blob(2, volume_id.bytes, sizeof(volume_id.bytes))
            .step();
    }

    /* Durable before the id is handed out: reserved ids never repeat. */
    tx.commit();

    return snap_id;
}

uint64_t VolumeStore::snap_commit(
    const RawstdUUID& volume_id, uint64_t snap_id,
    const std::vector<SnapMember>& members
) {
    VolumeDescriptor descriptor = _descriptor(volume_id);
    uint64_t nchunks =
        nchunks_of(descriptor.logical_size, descriptor.chunk_size);

    if (snap_id == 0) {
        rawstd_error("Snapshot id 0 is the live version\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    {
        /* The id must have been reserved by snap_begin(). */
        Stmt select(
            _db, "SELECT next_snap_id FROM volumes WHERE volume_id = ?;"
        );
        select.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes));
        if (!select.step() || snap_id >= select.column_int64(0)) {
            rawstd_error("Snapshot id was never reserved\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    /*
     * Every chunk must be covered: an unreadable snapshot is never
     * registered. (A degraded volume legitimately registers fewer members
     * per chunk than the policy width — recorded, not repaired.)
     */
    std::vector<bool> covered(nchunks, false);
    for (const SnapMember& m : members) {
        if (m.logical_index >= nchunks) {
            rawstd_error("Snapshot member out of volume bounds\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        covered[m.logical_index] = true;
    }
    for (bool c : covered) {
        if (!c) {
            rawstd_error("Snapshot does not cover every chunk\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    uint64_t map_epoch = descriptor.map_epoch + 1;

    Transaction tx(_db);

    {
        Stmt insert(
            _db, "INSERT INTO snapshots"
                 " (volume_id, snap_id, logical_size, created_at)"
                 " VALUES (?, ?, ?, ?);"
        );
        insert.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
            .bind_int64(2, snap_id)
            .bind_int64(3, descriptor.logical_size)
            .bind_int64(4, static_cast<uint64_t>(time(nullptr)))
            .step();
    }

    {
        Stmt insert(
            _db, "INSERT INTO snapshot_members"
                 " (volume_id, snap_id, logical_index, ost_id)"
                 " VALUES (?, ?, ?, ?);"
        );
        for (const SnapMember& m : members) {
            insert.reset();
            insert.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
                .bind_int64(2, snap_id)
                .bind_int64(3, m.logical_index)
                .bind_blob(4, m.ost_id.bytes, sizeof(m.ost_id.bytes))
                .step();
        }
    }

    {
        Stmt update(
            _db, "UPDATE volumes SET map_epoch = ? WHERE volume_id = ?;"
        );
        update.bind_int64(1, map_epoch)
            .bind_blob(2, volume_id.bytes, sizeof(volume_id.bytes))
            .step();
    }

    tx.commit();

    return map_epoch;
}

std::vector<SnapMember>
VolumeStore::snap_remove(const RawstdUUID& volume_id, uint64_t snap_id) {
    std::vector<SnapMember> ret;

    Transaction tx(_db);

    {
        Stmt select(
            _db, "SELECT logical_index, ost_id FROM snapshot_members"
                 " WHERE volume_id = ? AND snap_id = ?"
                 " ORDER BY logical_index, ost_id;"
        );
        select.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
            .bind_int64(2, snap_id);
        while (select.step()) {
            SnapMember m{};
            m.logical_index = select.column_int64(0);
            select.column_uuid(1, &m.ost_id);
            ret.push_back(m);
        }
    }

    {
        Stmt del(
            _db, "DELETE FROM snapshots"
                 " WHERE volume_id = ? AND snap_id = ?;"
        );
        del.bind_blob(1, volume_id.bytes, sizeof(volume_id.bytes))
            .bind_int64(2, snap_id)
            .step();
    }

    if (sqlite3_changes(_db) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    tx.commit();

    return ret;
}

} // namespace mds
} // namespace rawstor
