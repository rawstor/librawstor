#include <mds/store.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <cerrno>
#include <cstring>
#include <ctime>

namespace {

using rawstor::mdsserver::PlacementPolicy;

constexpr const char* SCHEMA =
    "CREATE TABLE IF NOT EXISTS objects ("
    "  id BLOB PRIMARY KEY,"
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
    "  id BLOB NOT NULL"
    "    REFERENCES objects(id) ON DELETE CASCADE,"
    "  logical_index INTEGER NOT NULL,"
    "  slot_index INTEGER NOT NULL,"
    "  ost_id BLOB NOT NULL,"
    "  PRIMARY KEY (id, logical_index, slot_index)"
    ") WITHOUT ROWID;"
    /*
     * No ON DELETE CASCADE from objects: an object with snapshots must
     * not silently disappear — remove() refuses with EBUSY.
     */
    "CREATE TABLE IF NOT EXISTS snapshots ("
    "  id BLOB NOT NULL REFERENCES objects(id),"
    "  snapshot_id BLOB NOT NULL,"
    "  logical_size INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  PRIMARY KEY (id, snapshot_id)"
    ") WITHOUT ROWID;"
    "CREATE TABLE IF NOT EXISTS snapshot_members ("
    "  id BLOB NOT NULL,"
    "  snapshot_id BLOB NOT NULL,"
    "  logical_index INTEGER NOT NULL,"
    "  ost_id BLOB NOT NULL,"
    "  PRIMARY KEY (id, snapshot_id, logical_index, ost_id),"
    "  FOREIGN KEY (id, snapshot_id)"
    "    REFERENCES snapshots(id, snapshot_id) ON DELETE CASCADE"
    ") WITHOUT ROWID;"
    /* Applied mutations by idempotency_key, for replaying a retried request. */
    "CREATE TABLE IF NOT EXISTS applied_mutations ("
    "  idempotency_key BLOB PRIMARY KEY,"
    "  kind INTEGER NOT NULL,"
    "  id BLOB NOT NULL,"
    "  result BLOB NOT NULL,"
    "  created_at INTEGER NOT NULL"
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
        // A null pointer would bind NULL, not an empty blob.
        if (size == 0) {
            data = "";
        }
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

    std::vector<unsigned char> column_blob(int pos) {
        const unsigned char* data =
            static_cast<const unsigned char*>(sqlite3_column_blob(_stmt, pos));
        int size = sqlite3_column_bytes(_stmt, pos);
        return std::vector<unsigned char>(data, data + size);
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
        rawstd_error("Object size 0\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    /* architecture.md: the chunk size must be a power of two. */
    if (chunk_size == 0 || (chunk_size & (chunk_size - 1)) != 0) {
        rawstd_error("Chunk size is not a power of two\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (logical_size % chunk_size != 0) {
        rawstd_error("Object size is not a multiple of chunk size\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (nchunks_of(logical_size, chunk_size) > UINT32_MAX) {
        rawstd_error("Object has too many chunks\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
}

void insert_chunks(
    sqlite3* db, const rawstor::mdsserver::Topology& topology,
    const RawstdUUID& id, uint64_t first_index, uint64_t end_index,
    uint64_t chunk_size, const PlacementPolicy& policy
) {
    (void)chunk_size;
    Stmt insert(
        db, "INSERT INTO chunk_map"
            " (id, logical_index, slot_index, ost_id)"
            " VALUES (?, ?, ?, ?);"
    );

    for (uint64_t index = first_index; index < end_index; ++index) {
        std::vector<rawstor::mdsserver::PlacementSlot> slots =
            rawstor::mdsserver::place(topology, id, index, policy);
        for (const rawstor::mdsserver::PlacementSlot& slot : slots) {
            insert.reset();
            insert.bind_blob(1, id.bytes, sizeof(id.bytes))
                .bind_int64(2, index)
                .bind_int64(3, slot.slot_index)
                .bind_blob(4, slot.ost_id.bytes, sizeof(slot.ost_id.bytes))
                .step();
        }
    }
}

/*
 * Idempotency records (ObjectStore's own doc comment on idempotency_key).
 * `kind` tells the mutations apart, so an idempotency_key replayed for a
 * different call is caught instead of answered with a foreign result.
 */
enum class MutationKind : unsigned {
    create = 1,
    resize = 2,
    remove = 3,
    snap_commit = 4,
    snap_remove = 5,
};

// How long a record is kept: far beyond any client's retry window.
const uint64_t mutation_record_ttl_seconds = 24 * 60 * 60;

/* A recorded result, packed field by field in host byte order. */
class ResultWriter final {
private:
    std::vector<unsigned char> _data;

public:
    ResultWriter() : _data() {}

    template <typename T>
    ResultWriter& put(const T& value) {
        const unsigned char* p = reinterpret_cast<const unsigned char*>(&value);
        _data.insert(_data.end(), p, p + sizeof(value));
        return *this;
    }

    const std::vector<unsigned char>& data() const noexcept { return _data; }
};

class ResultReader final {
private:
    const std::vector<unsigned char>& _data;
    size_t _off;

public:
    explicit ResultReader(const std::vector<unsigned char>& data) :
        _data(data),
        _off(0) {}

    template <typename T>
    T get() {
        T value;
        if (sizeof(value) > _data.size() - _off) {
            rawstd_error("MDS store: truncated op record\n");
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        memcpy(&value, _data.data() + _off, sizeof(value));
        _off += sizeof(value);
        return value;
    }
};

/*
 * The recorded result of `idempotency_key`, if it was already applied; EINVAL
 * if it was applied as a different call. A nil idempotency_key never replays.
 */
std::optional<std::vector<unsigned char>> replay_mutation(
    sqlite3* db, const RawstdUUID& idempotency_key, MutationKind kind,
    const RawstdUUID& id
) {
    if (rawstd_uuid_is_nil(&idempotency_key)) {
        return std::nullopt;
    }
    Stmt select(
        db, "SELECT kind, id, result FROM applied_mutations WHERE "
            "idempotency_key = ?;"
    );
    select.bind_blob(1, idempotency_key.bytes, sizeof(idempotency_key.bytes));
    if (!select.step()) {
        return std::nullopt;
    }
    RawstdUUID recorded_id;
    select.column_uuid(1, &recorded_id);
    if (select.column_int64(0) != static_cast<uint64_t>(kind) ||
        rawstd_uuid_cmp(&recorded_id, &id) != 0) {
        rawstd_error(
            "MDS store: idempotency_key reused for a different request\n"
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return select.column_blob(2);
}

/* Inside the mutation's own transaction; also drops expired records. */
void record_mutation(
    sqlite3* db, const RawstdUUID& idempotency_key, MutationKind kind,
    const RawstdUUID& id, const std::vector<unsigned char>& result
) {
    if (rawstd_uuid_is_nil(&idempotency_key)) {
        return;
    }
    uint64_t now = static_cast<uint64_t>(time(nullptr));
    {
        Stmt expire(db, "DELETE FROM applied_mutations WHERE created_at < ?;");
        expire
            .bind_int64(
                1, now > mutation_record_ttl_seconds
                       ? now - mutation_record_ttl_seconds
                       : 0
            )
            .step();
    }
    Stmt insert(
        db, "INSERT OR REPLACE INTO applied_mutations (idempotency_key, kind, "
            "id, result, created_at)"
            " VALUES (?, ?, ?, ?, ?);"
    );
    insert.bind_blob(1, idempotency_key.bytes, sizeof(idempotency_key.bytes))
        .bind_int64(2, static_cast<uint64_t>(kind))
        .bind_blob(3, id.bytes, sizeof(id.bytes))
        .bind_blob(4, result.data(), result.size())
        .bind_int64(5, now)
        .step();
}

std::vector<unsigned char>
encode_map(const rawstor::mdsserver::ObjectMap& map) {
    ResultWriter w;
    const rawstor::mdsserver::ObjectDescriptor& d = map.descriptor;
    w.put(d.id)
        .put(d.logical_size)
        .put(d.chunk_size)
        .put(static_cast<uint64_t>(d.policy.width))
        .put(static_cast<uint64_t>(d.policy.failure_domain))
        .put(d.policy.stripe_width)
        .put(d.policy.seed)
        .put(d.map_epoch)
        .put(static_cast<uint64_t>(map.chunks.size()));
    for (const auto& slots : map.chunks) {
        w.put(static_cast<uint64_t>(slots.size()));
        for (const rawstor::mdsserver::PlacementSlot& slot : slots) {
            w.put(slot.slot_index).put(slot.ost_id);
        }
    }
    return w.data();
}

rawstor::mdsserver::ObjectMap
decode_map(const std::vector<unsigned char>& data) {
    ResultReader r(data);
    rawstor::mdsserver::ObjectMap map{};
    rawstor::mdsserver::ObjectDescriptor& d = map.descriptor;
    d.id = r.get<RawstdUUID>();
    d.logical_size = r.get<uint64_t>();
    d.chunk_size = r.get<uint64_t>();
    d.policy.width = static_cast<unsigned>(r.get<uint64_t>());
    d.policy.failure_domain =
        rawstor::mdsserver::level_of(static_cast<unsigned>(r.get<uint64_t>()));
    d.policy.stripe_width = r.get<uint64_t>();
    d.policy.seed = r.get<uint64_t>();
    d.map_epoch = r.get<uint64_t>();
    map.chunks.resize(r.get<uint64_t>());
    for (auto& slots : map.chunks) {
        slots.resize(r.get<uint64_t>());
        for (rawstor::mdsserver::PlacementSlot& slot : slots) {
            slot.slot_index = r.get<uint8_t>();
            slot.ost_id = r.get<RawstdUUID>();
        }
    }
    return map;
}

} // namespace

namespace rawstor {
namespace mdsserver {

ObjectStore::ObjectStore(const std::string& path, Topology topology) :
    _mutex(),
    _db(nullptr),
    _topology(std::make_shared<const Topology>(std::move(topology))) {
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

ObjectStore::~ObjectStore() {
    sqlite3_close(_db);
}

ObjectDescriptor ObjectStore::_descriptor(const RawstdUUID& id) {
    Stmt select(
        _db, "SELECT logical_size, chunk_size, width, failure_domain,"
             " stripe_width, placement_seed, map_epoch"
             " FROM objects WHERE id = ?;"
    );
    select.bind_blob(1, id.bytes, sizeof(id.bytes));

    if (!select.step()) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    ObjectDescriptor ret{};
    ret.id = id;
    ret.logical_size = select.column_int64(0);
    ret.chunk_size = select.column_int64(1);
    ret.policy.width = static_cast<unsigned>(select.column_int64(2));
    ret.policy.failure_domain =
        level_of(static_cast<unsigned>(select.column_int64(3)));
    ret.policy.stripe_width = select.column_int64(4);
    ret.policy.seed = select.column_int64(5);
    ret.map_epoch = select.column_int64(6);
    return ret;
}

std::shared_ptr<const Topology> ObjectStore::topology() {
    std::lock_guard<std::mutex> lock(_mutex);
    return _topology;
}

void ObjectStore::check_topology(const Topology& topology) {
    std::lock_guard<std::mutex> lock(_mutex);
    _check_topology(topology);
}

void ObjectStore::_check_topology(const Topology& topology) {
    Stmt select(
        _db, "SELECT ost_id FROM chunk_map"
             " UNION SELECT ost_id FROM snapshot_members;"
    );

    bool missing = false;
    while (select.step()) {
        RawstdUUID ost_id;
        select.column_uuid(0, &ost_id);

        bool found = false;
        for (const TopologyOST& ost : topology.osts()) {
            if (rawstd_uuid_cmp(&ost.id, &ost_id) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            RawstdUUIDString ost_id_str;
            rawstd_uuid_to_string(&ost_id, &ost_id_str);
            rawstd_error(
                "OST %s still holds chunks but is missing from the "
                "topology\n",
                ost_id_str
            );
            missing = true;
        }
    }

    if (missing) {
        RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
    }
}

void ObjectStore::set_topology(Topology topology) {
    std::lock_guard<std::mutex> lock(_mutex);
    _check_topology(topology);
    _topology = std::make_shared<const Topology>(std::move(topology));
}

ObjectDescriptor ObjectStore::create(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    uint64_t logical_size, uint64_t chunk_size, const PlacementPolicy& policy
) {
    std::lock_guard<std::mutex> lock(_mutex);
    validate_geometry(logical_size, chunk_size);

    if (replay_mutation(_db, idempotency_key, MutationKind::create, id)) {
        try {
            return _descriptor(id);
        } catch (const std::system_error& e) {
            if (e.code().value() != ENOENT) {
                throw;
            }
            // Created, then removed again by the caller's own rollback:
            // this retry creates it afresh (record_mutation() below replaces
            // the stale record).
        }
    }

    ObjectDescriptor ret{};
    ret.id = id;
    ret.logical_size = logical_size;
    ret.chunk_size = chunk_size;
    ret.policy = policy;
    ret.map_epoch = 1;

    uint64_t nchunks = nchunks_of(logical_size, chunk_size);

    /* Hard-fails on an unsatisfiable topology before anything lands. */
    place(*_topology, ret.id, 0, policy);

    Transaction tx(_db);

    {
        Stmt insert(
            _db, "INSERT INTO objects"
                 " (id, logical_size, chunk_size, width,"
                 " failure_domain, stripe_width, placement_seed, map_epoch,"
                 " created_at)"
                 " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"
        );
        insert.bind_blob(1, ret.id.bytes, sizeof(ret.id.bytes))
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

    insert_chunks(_db, *_topology, ret.id, 0, nchunks, chunk_size, ret.policy);

    record_mutation(_db, idempotency_key, MutationKind::create, id, {});

    tx.commit();

    return ret;
}

ObjectMap
ObjectStore::open(const RawstdUUID& id, const RawstdUUID& snapshot_id) {
    std::lock_guard<std::mutex> lock(_mutex);
    if (!rawstd_uuid_is_nil(&snapshot_id)) {
        return _open_snapshot(id, snapshot_id);
    }
    return _open_live(id);
}

ObjectMap ObjectStore::_open_live(const RawstdUUID& id) {
    ObjectMap ret{};
    ret.descriptor = _descriptor(id);

    uint64_t nchunks =
        nchunks_of(ret.descriptor.logical_size, ret.descriptor.chunk_size);
    ret.chunks.resize(nchunks);

    Stmt select(
        _db, "SELECT logical_index, slot_index, ost_id FROM chunk_map"
             " WHERE id = ?"
             " ORDER BY logical_index, slot_index;"
    );
    select.bind_blob(1, id.bytes, sizeof(id.bytes));

    while (select.step()) {
        uint64_t index = select.column_int64(0);
        if (index >= nchunks) {
            rawstd_error("MDS store: chunk index out of object bounds\n");
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

ResizeResult ObjectStore::resize(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t new_size
) {
    std::lock_guard<std::mutex> lock(_mutex);
    if (std::optional<std::vector<unsigned char>> recorded =
            replay_mutation(_db, idempotency_key, MutationKind::resize, id)) {
        ResultReader r(*recorded);
        ResizeResult ret{};
        ret.map_epoch = r.get<uint64_t>();
        ret.old_nchunks = r.get<uint64_t>();
        return ret;
    }

    ObjectDescriptor descriptor = _descriptor(id);

    validate_geometry(new_size, descriptor.chunk_size);

    /* Grow-only in v1: shrink interacts with GC and snapshots. */
    if (new_size < descriptor.logical_size) {
        rawstd_error("Object shrink is not supported\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    uint64_t old_chunks =
        nchunks_of(descriptor.logical_size, descriptor.chunk_size);
    uint64_t new_chunks = nchunks_of(new_size, descriptor.chunk_size);
    uint64_t map_epoch = descriptor.map_epoch + 1;

    Transaction tx(_db);

    {
        Stmt update(
            _db, "UPDATE objects SET logical_size = ?, map_epoch = ?"
                 " WHERE id = ?;"
        );
        update.bind_int64(1, new_size)
            .bind_int64(2, map_epoch)
            .bind_blob(3, id.bytes, sizeof(id.bytes))
            .step();
    }

    insert_chunks(
        _db, *_topology, id, old_chunks, new_chunks, descriptor.chunk_size,
        descriptor.policy
    );

    record_mutation(
        _db, idempotency_key, MutationKind::resize, id,
        ResultWriter().put(map_epoch).put(old_chunks).data()
    );

    tx.commit();

    return ResizeResult{.map_epoch = map_epoch, .old_nchunks = old_chunks};
}

void ObjectStore::reconstruct(const std::vector<ScanRecord>& records) {
    std::lock_guard<std::mutex> lock(_mutex);
    struct Chunk {
        /* Scan order becomes the slot order. */
        std::vector<RawstdUUID> ost_ids;
    };
    struct Object {
        uint64_t chunk_size;
        unsigned width;
        std::map<uint64_t, Chunk> chunks;
    };

    std::map<std::string, Object> objects;

    for (const ScanRecord& r : records) {
        /* Witness records are metadata-only votes, not data slots. */
        if (r.meta.member_role != RAWSTOR_MEMBER_DATA) {
            continue;
        }

        RawstdUUIDString obj_str;
        rawstd_uuid_to_string(&r.obj_id, &obj_str);

        // `r.obj_id` is the whole object's own id directly (docs/mds.md,
        // "Chunk identity": obj_id = id) -- including for a standalone
        // object, which reconstructs as an "object" of a single chunk,
        // byte-for-byte compatible with a plain object.
        std::string key(
            reinterpret_cast<const char*>(r.obj_id.bytes),
            sizeof(r.obj_id.bytes)
        );

        auto [it, fresh] = objects.try_emplace(key);
        Object& o = it->second;
        if (fresh) {
            o.chunk_size = r.meta.spec.chunk_size;
            o.width = r.meta.spec.width;
            if (o.chunk_size == 0 || (o.chunk_size & (o.chunk_size - 1)) != 0 ||
                o.width == 0) {
                rawstd_error(
                    "reconstruct: %s: malformed stored identity\n", obj_str
                );
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
        } else if (o.chunk_size != r.meta.spec.chunk_size ||
                   o.width != r.meta.spec.width) {
            rawstd_error(
                "reconstruct: %s: identity conflicts with its object\n", obj_str
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        // logical_index is not carried on the wire -- it's derived from
        // the chunk's own byte offset (rawstor_target_offset(),
        // ScanRecord's own doc comment), the inverse of the formula
        // chunk_slot_target() in mds_backend.cpp stamps the offset with.
        uint64_t logical_index = r.offset / o.chunk_size;

        Chunk& c = o.chunks[logical_index];

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
    }

    Transaction tx(_db);

    exec(
        _db, "DELETE FROM snapshot_members;"
             "DELETE FROM snapshots;"
             "DELETE FROM objects;"
    );

    for (const auto& [key, o] : objects) {
        RawstdUUID id;
        memcpy(id.bytes, key.data(), sizeof(id.bytes));
        RawstdUUIDString id_str;
        rawstd_uuid_to_string(&id, &id_str);

        /* std::map is ordered: the last key is the highest index. */
        uint64_t max_index = o.chunks.rbegin()->first;
        if (o.chunks.size() != max_index + 1) {
            rawstd_error(
                "reconstruct: %s: no surviving copy of %llu of %llu "
                "chunks\n",
                id_str,
                static_cast<unsigned long long>(
                    max_index + 1 - o.chunks.size()
                ),
                static_cast<unsigned long long>(max_index + 1)
            );
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        /* Every chunk is exactly chunk_size (validate_geometry()). */
        uint64_t logical_size = (max_index + 1) * o.chunk_size;

        /*
         * The policy knobs are not persisted on chunks: existing chunks
         * keep their placement (the map below is explicit), the rebuilt
         * descriptor constrains only future resizes — weakest domain, so
         * a reduced post-disaster topology never fails validation.
         */
        {
            Stmt insert(
                _db, "INSERT INTO objects"
                     " (id, logical_size, chunk_size, width,"
                     " failure_domain, stripe_width, placement_seed,"
                     " map_epoch, created_at)"
                     " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"
            );
            insert.bind_blob(1, id.bytes, sizeof(id.bytes))
                .bind_int64(2, logical_size)
                .bind_int64(3, o.chunk_size)
                .bind_int64(4, o.width)
                .bind_int64(
                    5, static_cast<uint64_t>(rawstor::mdsserver::Level::OST)
                )
                .bind_int64(6, STRIPE_ALL)
                .bind_int64(7, 0)
                .bind_int64(8, 1)
                .bind_int64(9, static_cast<uint64_t>(time(nullptr)))
                .step();
        }

        {
            Stmt insert(
                _db, "INSERT INTO chunk_map"
                     " (id, logical_index, slot_index, ost_id)"
                     " VALUES (?, ?, ?, ?);"
            );
            for (const auto& [index, chunk] : o.chunks) {
                for (size_t slot = 0; slot < chunk.ost_ids.size(); ++slot) {
                    insert.reset();
                    insert.bind_blob(1, id.bytes, sizeof(id.bytes))
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
    }

    tx.commit();

    rawstd_info(
        "reconstruct: %zu objects rebuilt from %zu records\n", objects.size(),
        records.size()
    );
}

ObjectMap
ObjectStore::remove(const RawstdUUID& idempotency_key, const RawstdUUID& id) {
    std::lock_guard<std::mutex> lock(_mutex);
    if (std::optional<std::vector<unsigned char>> recorded =
            replay_mutation(_db, idempotency_key, MutationKind::remove, id)) {
        return decode_map(*recorded);
    }

    Transaction tx(_db);

    {
        /* An object with snapshots must not silently disappear. */
        Stmt busy(
            _db, "SELECT snapshot_id FROM snapshots WHERE id = ? LIMIT 1;"
        );
        busy.bind_blob(1, id.bytes, sizeof(id.bytes));
        if (busy.step()) {
            rawstd_error("Object has snapshots; remove them first\n");
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }
    }

    // ENOENT if there is no such object.
    ObjectMap ret = _open_live(id);

    {
        Stmt del(_db, "DELETE FROM objects WHERE id = ?;");
        del.bind_blob(1, id.bytes, sizeof(id.bytes)).step();
    }

    record_mutation(
        _db, idempotency_key, MutationKind::remove, id, encode_map(ret)
    );

    tx.commit();

    return ret;
}

ObjectMap ObjectStore::_open_snapshot(
    const RawstdUUID& id, const RawstdUUID& snapshot_id
) {
    ObjectMap ret{};
    ret.descriptor = _descriptor(id);

    {
        Stmt select(
            _db, "SELECT logical_size FROM snapshots"
                 " WHERE id = ? AND snapshot_id = ?;"
        );
        select.bind_blob(1, id.bytes, sizeof(id.bytes))
            .bind_blob(2, snapshot_id.bytes, sizeof(snapshot_id.bytes));
        if (!select.step()) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
        }
        /* The size the object had when the snapshot was taken. */
        ret.descriptor.logical_size = select.column_int64(0);
    }

    uint64_t nchunks =
        nchunks_of(ret.descriptor.logical_size, ret.descriptor.chunk_size);
    ret.chunks.resize(nchunks);

    Stmt select(
        _db, "SELECT logical_index, ost_id FROM snapshot_members"
             " WHERE id = ? AND snapshot_id = ?"
             " ORDER BY logical_index, ost_id;"
    );
    select.bind_blob(1, id.bytes, sizeof(id.bytes))
        .bind_blob(2, snapshot_id.bytes, sizeof(snapshot_id.bytes));

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

uint64_t ObjectStore::snap_commit(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& snapshot_id, const std::vector<SnapMember>& members
) {
    std::lock_guard<std::mutex> lock(_mutex);
    if (std::optional<std::vector<unsigned char>> recorded = replay_mutation(
            _db, idempotency_key, MutationKind::snap_commit, id
        )) {
        return ResultReader(*recorded).get<uint64_t>();
    }

    ObjectDescriptor descriptor = _descriptor(id);
    uint64_t nchunks =
        nchunks_of(descriptor.logical_size, descriptor.chunk_size);

    if (rawstd_uuid_is_nil(&snapshot_id)) {
        rawstd_error("A nil snapshot_id is the live version\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    /*
     * Every chunk must be covered: an unreadable snapshot is never
     * registered. (A degraded object legitimately registers fewer members
     * per chunk than the policy width — recorded, not repaired.)
     */
    std::vector<bool> covered(nchunks, false);
    for (const SnapMember& m : members) {
        if (m.logical_index >= nchunks) {
            rawstd_error("Snapshot member out of object bounds\n");
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
                 " (id, snapshot_id, logical_size, created_at)"
                 " VALUES (?, ?, ?, ?);"
        );
        insert.bind_blob(1, id.bytes, sizeof(id.bytes))
            .bind_blob(2, snapshot_id.bytes, sizeof(snapshot_id.bytes))
            .bind_int64(3, descriptor.logical_size)
            .bind_int64(4, static_cast<uint64_t>(time(nullptr)))
            .step();
    }

    {
        Stmt insert(
            _db, "INSERT INTO snapshot_members"
                 " (id, snapshot_id, logical_index, ost_id)"
                 " VALUES (?, ?, ?, ?);"
        );
        for (const SnapMember& m : members) {
            insert.reset();
            insert.bind_blob(1, id.bytes, sizeof(id.bytes))
                .bind_blob(2, snapshot_id.bytes, sizeof(snapshot_id.bytes))
                .bind_int64(3, m.logical_index)
                .bind_blob(4, m.ost_id.bytes, sizeof(m.ost_id.bytes))
                .step();
        }
    }

    {
        Stmt update(_db, "UPDATE objects SET map_epoch = ? WHERE id = ?;");
        update.bind_int64(1, map_epoch)
            .bind_blob(2, id.bytes, sizeof(id.bytes))
            .step();
    }

    record_mutation(
        _db, idempotency_key, MutationKind::snap_commit, id,
        ResultWriter().put(map_epoch).data()
    );

    tx.commit();

    return map_epoch;
}

std::vector<SnapMember> ObjectStore::snap_remove(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& snapshot_id
) {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<SnapMember> ret;
    if (std::optional<std::vector<unsigned char>> recorded = replay_mutation(
            _db, idempotency_key, MutationKind::snap_remove, id
        )) {
        ResultReader r(*recorded);
        ret.resize(r.get<uint64_t>());
        for (SnapMember& m : ret) {
            m.logical_index = r.get<uint64_t>();
            m.ost_id = r.get<RawstdUUID>();
        }
        return ret;
    }

    Transaction tx(_db);

    {
        Stmt select(
            _db, "SELECT logical_index, ost_id FROM snapshot_members"
                 " WHERE id = ? AND snapshot_id = ?"
                 " ORDER BY logical_index, ost_id;"
        );
        select.bind_blob(1, id.bytes, sizeof(id.bytes))
            .bind_blob(2, snapshot_id.bytes, sizeof(snapshot_id.bytes));
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
                 " WHERE id = ? AND snapshot_id = ?;"
        );
        del.bind_blob(1, id.bytes, sizeof(id.bytes))
            .bind_blob(2, snapshot_id.bytes, sizeof(snapshot_id.bytes))
            .step();
    }

    if (sqlite3_changes(_db) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    ResultWriter w;
    w.put(static_cast<uint64_t>(ret.size()));
    for (const SnapMember& m : ret) {
        w.put(m.logical_index).put(m.ost_id);
    }
    record_mutation(
        _db, idempotency_key, MutationKind::snap_remove, id, w.data()
    );

    tx.commit();

    return ret;
}

} // namespace mdsserver
} // namespace rawstor
