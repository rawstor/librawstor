#include <mds/store.hpp>
#include <rawstor/location.h>
#include <rawstor/pki.h>
#include <rawstor/protocol.h>
#include <rawtls/authorization.hpp>

#include <rawstd/caspaxos.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <cerrno>
#include <cstring>
#include <ctime>

namespace {

using rawstor::mdsserver::PlacementPolicy;

/*
 * An object has one account, its owner, recorded when it is created
 * (docs/accounts.md); 16 zero bytes for none. The accounts table is the
 * registry of the accounts an object can be created for.
 */
constexpr const char* SCHEMA =
    "CREATE TABLE IF NOT EXISTS accounts ("
    " id BLOB PRIMARY KEY, created_at INTEGER NOT NULL"
    ") WITHOUT ROWID;"
    "CREATE TABLE IF NOT EXISTS witnesses ("
    " id BLOB NOT NULL, chunk_offset INTEGER NOT NULL, record BLOB NOT NULL,"
    " account_id BLOB NOT NULL,"
    " PRIMARY KEY(id, chunk_offset)"
    ") WITHOUT ROWID;"
    /*
     * The topology: every OST that has registered (docs/mds.md, "OST
     * registration") and the MDS's own witness. `roles` is a bitmask of
     * role_data and role_witness, `domain` the failure domain path
     * ("[[[dc/]row/]rack/]server"), and `used`, `total`, `members` and
     * `members_hash` its latest sample (all 0 for none).
     */
    "CREATE TABLE IF NOT EXISTS topology ("
    " id BLOB PRIMARY KEY, location TEXT NOT NULL,"
    " weight INTEGER NOT NULL DEFAULT 0, roles INTEGER NOT NULL DEFAULT 3,"
    " domain TEXT NOT NULL DEFAULT '',"
    " used INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT 0,"
    " members INTEGER NOT NULL DEFAULT 0,"
    " members_hash INTEGER NOT NULL DEFAULT 0"
    ") WITHOUT ROWID;"
    "CREATE TABLE IF NOT EXISTS objects ("
    "  id BLOB PRIMARY KEY,"
    "  account_id BLOB NOT NULL,"
    "  logical_size INTEGER NOT NULL,"
    "  chunk_size INTEGER NOT NULL,"
    "  width INTEGER NOT NULL,"
    "  failure_domain INTEGER NOT NULL,"
    "  stripe_width INTEGER NOT NULL,"
    "  placement_seed INTEGER NOT NULL,"
    "  map_version INTEGER NOT NULL,"
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
     * No ON DELETE CASCADE from objects: an object with versions must
     * not silently disappear — remove() refuses with EBUSY.
     */
    "CREATE TABLE IF NOT EXISTS versions ("
    "  id BLOB NOT NULL REFERENCES objects(id),"
    "  version_id BLOB NOT NULL,"
    "  logical_size INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  PRIMARY KEY (id, version_id)"
    ") WITHOUT ROWID;"
    "CREATE TABLE IF NOT EXISTS version_members ("
    "  id BLOB NOT NULL,"
    "  version_id BLOB NOT NULL,"
    "  logical_index INTEGER NOT NULL,"
    "  ost_id BLOB NOT NULL,"
    "  PRIMARY KEY (id, version_id, logical_index, ost_id),"
    "  FOREIGN KEY (id, version_id)"
    "    REFERENCES versions(id, version_id) ON DELETE CASCADE"
    ") WITHOUT ROWID;"
    /* The slots and version members one topology entry holds. */
    "CREATE INDEX IF NOT EXISTS chunk_map_by_ost ON chunk_map(ost_id, id);"
    "CREATE INDEX IF NOT EXISTS version_members_by_ost "
    "ON version_members(ost_id, id);"
    /* Applied mutations by idempotency_key, for replaying a retried request. */
    "CREATE TABLE IF NOT EXISTS applied_mutations ("
    "  idempotency_key BLOB PRIMARY KEY,"
    "  type INTEGER NOT NULL,"
    "  id BLOB NOT NULL,"
    "  result BLOB NOT NULL,"
    "  created_at INTEGER NOT NULL"
    ") WITHOUT ROWID;"
    "CREATE TABLE IF NOT EXISTS removed_owners ("
    " idempotency_key BLOB PRIMARY KEY REFERENCES "
    "applied_mutations(idempotency_key) ON DELETE CASCADE,"
    " id BLOB NOT NULL, account_id BLOB NOT NULL"
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

    Stmt& bind_text(int pos, const std::string& value) {
        if (sqlite3_bind_text(
                _stmt, pos, value.c_str(), -1, SQLITE_TRANSIENT
            ) != SQLITE_OK) {
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

    std::string column_text(int pos) {
        const unsigned char* text = sqlite3_column_text(_stmt, pos);
        return text == nullptr
                   ? std::string()
                   : std::string(reinterpret_cast<const char*>(text));
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

/* Returns every OST that gets a slot. */
std::vector<RawstdUUID> insert_chunks(
    sqlite3* db, const rawstor::mdsserver::Topology& topology,
    const RawstdUUID& id, uint64_t first_index, uint64_t end_index,
    uint64_t chunk_size, const PlacementPolicy& policy
) {
    std::vector<RawstdUUID> touched;
    (void)chunk_size;
    Stmt insert(
        db, "INSERT INTO chunk_map"
            " (id, logical_index, slot_index, ost_id)"
            " VALUES (?, ?, ?, ?);"
    );

    for (uint64_t index = first_index; index < end_index; ++index) {
        std::vector<rawstor::mdsserver::PlacementSlot> slots =
            rawstor::mdsserver::place_chunk(topology, id, index, policy);
        for (const rawstor::mdsserver::PlacementSlot& slot : slots) {
            insert.reset();
            insert.bind_blob(1, id.bytes, sizeof(id.bytes))
                .bind_int64(2, index)
                .bind_int64(3, slot.slot_index)
                .bind_blob(4, slot.ost_id.bytes, sizeof(slot.ost_id.bytes))
                .step();
            touched.push_back(slot.ost_id);
        }
    }
    return touched;
}

/*
 * Idempotency records (ObjectStore's own doc comment on idempotency_key).
 * `type` tells the mutations apart, so an idempotency_key replayed for a
 * different call is caught instead of answered with a foreign result.
 */
enum class MutationType : unsigned {
    create = 1,
    resize = 2,
    remove = 3,
    commit_version = 4,
    remove_version = 5,
    create_account = 6,
    remove_account = 7,
    transfer = 8,
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
    sqlite3* db, const RawstdUUID& idempotency_key, MutationType type,
    const RawstdUUID& id
) {
    if (rawstd_uuid_is_nil(&idempotency_key)) {
        return std::nullopt;
    }
    Stmt select(
        db, "SELECT type, id, result FROM applied_mutations WHERE "
            "idempotency_key = ?;"
    );
    select.bind_blob(1, idempotency_key.bytes, sizeof(idempotency_key.bytes));
    if (!select.step()) {
        return std::nullopt;
    }
    RawstdUUID recorded_id;
    select.column_uuid(1, &recorded_id);
    if (select.column_int64(0) != static_cast<uint64_t>(type) ||
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
    sqlite3* db, const RawstdUUID& idempotency_key, MutationType type,
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
        db, "INSERT OR REPLACE INTO applied_mutations (idempotency_key, type, "
            "id, result, created_at)"
            " VALUES (?, ?, ?, ?, ?);"
    );
    insert.bind_blob(1, idempotency_key.bytes, sizeof(idempotency_key.bytes))
        .bind_int64(2, static_cast<uint64_t>(type))
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
        .put(d.map_version)
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
    d.map_version = r.get<uint64_t>();
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

/* The bits of the topology table's `roles`. */
constexpr uint64_t role_data = 1;
constexpr uint64_t role_witness = 2;

std::set<rawstor::mdsserver::Role> roles_of(uint64_t bits) {
    std::set<rawstor::mdsserver::Role> roles;
    if (bits & role_data) {
        roles.insert(rawstor::mdsserver::Role::Data);
    }
    if (bits & role_witness) {
        roles.insert(rawstor::mdsserver::Role::Witness);
    }
    return roles;
}

/* The failure domain path of an entry, as it registered it. */
std::string domain_of(const rawstor::mdsserver::TopologyOST& ost) {
    std::string ret;
    for (const std::string& part : ost.path) {
        if (part.empty()) {
            continue;
        }
        if (!ret.empty()) {
            ret += '/';
        }
        ret += part;
    }
    return ret;
}

/*
 * One physical location URI: an entry is one placement slot, i.e. one member
 * with one vote in the mirror quorum (docs/mds.md). EINVAL otherwise.
 */
void check_location(const std::string& location) {
    bool valid = false;
    try {
        valid = !location.empty() &&
                rawstd::URI::uriv(location.c_str()).size() == 1 &&
                !rawstd::URI(location).scheme().empty() &&
                rawstd::URI(location).scheme() != "mds" &&
                rawstd::URI(location).userinfo().empty();
    } catch (const std::system_error&) {
    }
    if (!valid) {
        rawstd_error(
            "Expected a single physical location without user "
            "information: %s\n",
            rawstor::printable_location(location).c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
}

std::string key_of(const RawstdUUID& id) {
    return std::string(
        reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes)
    );
}

} // namespace

namespace rawstor {
namespace mdsserver {

ObjectStore::ObjectStore(const std::string& path, const Opts& opts) :
    _mutex(),
    _db(nullptr),
    _opts(opts),
    _lease(std::chrono::milliseconds(uint64_t{opts.heartbeat_interval} * 3)),
    _started(Clock::now()),
    _last_sweep(_started),
    _topology(std::make_shared<const Topology>()) {
    if (opts.heartbeat_interval == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
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
        exec(_db, "PRAGMA journal_mode=WAL;");
        exec(_db, "PRAGMA synchronous=FULL;");
        exec(_db, "PRAGMA foreign_keys=ON;");
        _check_layout();
        exec(_db, SCHEMA);
        _register_default_account();
        exec(_db, "PRAGMA user_version=1;");
        _load_topology();
    } catch (...) {
        sqlite3_close(_db);
        throw;
    }
}

ObjectStore::~ObjectStore() {
    sqlite3_close(_db);
}

/*
 * A store written before objects had an account has tables without it; it is
 * refused rather than misread.
 */
void ObjectStore::_check_layout() {
    Stmt version(_db, "PRAGMA user_version;");
    if (!version.step()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    uint64_t user_version = version.column_int64(0);
    Stmt tables(
        _db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
             "name='objects';"
    );
    if (!tables.step()) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    bool existing = tables.column_int64(0) != 0;
    if (user_version != 1 && (user_version != 0 || existing)) {
        rawstd_error("MDS store has an unsupported layout\n");
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
}

/* Every store registers the default account, which can neither be created nor
 * removed. */
void ObjectStore::_register_default_account() {
    RawstdUUID account;
    rawstd_uuid_from_string(&account, RAWSTOR_DEFAULT_ACCOUNT);
    Stmt insert(
        _db, "INSERT OR IGNORE INTO accounts (id, created_at) VALUES (?, ?);"
    );
    insert.bind_blob(1, account.bytes, sizeof(account.bytes))
        .bind_int64(2, static_cast<uint64_t>(time(nullptr)))
        .step();
}

/* A nil account is none; any other is registered. */
void ObjectStore::_require_account(const RawstdUUID& account) {
    if (rawstd_uuid_is_nil(&account)) {
        return;
    }
    Stmt select(_db, "SELECT 1 FROM accounts WHERE id = ?;");
    select.bind_blob(1, account.bytes, sizeof(account.bytes));
    if (!select.step()) {
        rawstd_error("Unknown account\n");
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
}

ObjectDescriptor ObjectStore::_descriptor(const RawstdUUID& id) {
    Stmt select(
        _db, "SELECT logical_size, chunk_size, width, failure_domain,"
             " stripe_width, placement_seed, map_version"
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
    ret.map_version = select.column_int64(6);
    return ret;
}

void ObjectStore::create_witness(
    const RawstdUUID& account, const RawstdUUID& id, uint64_t offset,
    const RawstorObjectSpec& spec
) {
    if (rawstd_uuid_is_nil(&id) || spec.width == 0 ||
        spec.width > RAWSTOR_OBJECT_MAX_WIDTH ||
        (spec.chunk_size != 0 &&
         (spec.chunk_size & (spec.chunk_size - 1)) != 0)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    RawstorObjectMeta meta{};
    memcpy(meta.account_id, account.bytes, sizeof(meta.account_id));
    meta.spec = spec;
    meta.member_role = RAWSTOR_MEMBER_WITNESS;
    meta.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    RawstorFrameMetaPayload record{};
    if (int error = rawstor_frame_meta_encode(&record, &meta)) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    Stmt stmt(
        _db, "INSERT INTO witnesses(id,chunk_offset,record,account_id) "
             "VALUES(?,?,?,?)"
    );
    stmt.bind_blob(1, id.bytes, sizeof(id.bytes))
        .bind_int64(2, offset)
        .bind_blob(3, &record, sizeof(record))
        .bind_blob(4, account.bytes, sizeof(account.bytes))
        .step();
}

RawstorObjectMeta
ObjectStore::_load_witness(const RawstdUUID& id, uint64_t offset) {
    Stmt stmt(
        _db, "SELECT record FROM witnesses WHERE id=? AND chunk_offset=?"
    );
    stmt.bind_blob(1, id.bytes, sizeof(id.bytes)).bind_int64(2, offset);
    if (!stmt.step()) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    auto bytes = stmt.column_blob(0);
    if (bytes.size() != sizeof(RawstorFrameMetaPayload)) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    RawstorFrameMetaPayload record{};
    memcpy(&record, bytes.data(), sizeof(record));
    RawstorObjectMeta meta{};
    if (int error = rawstor_frame_meta_decode(&record, &meta)) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }
    return meta;
}

void ObjectStore::_store_witness(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectMeta& meta
) {
    RawstorFrameMetaPayload record{};
    if (int error = rawstor_frame_meta_encode(&record, &meta)) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }
    Stmt update(
        _db, "UPDATE witnesses SET record=? WHERE id=? AND chunk_offset=?"
    );
    update.bind_blob(1, &record, sizeof(record))
        .bind_blob(2, id.bytes, sizeof(id.bytes))
        .bind_int64(3, offset)
        .step();
}

RawstorObjectMeta
ObjectStore::witness_meta(const RawstdUUID& id, uint64_t offset) {
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    return _load_witness(id, offset);
}

RawstorObjectMeta ObjectStore::sync_prepare(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectBallot& ballot,
    bool& ok
) {
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    Transaction tx(_db);
    RawstorObjectMeta meta = _load_witness(id, offset);
    rawstd::caspaxos::Acceptor<RawstorObjectConfig> state{
        {meta.promised.counter, meta.promised.proposer},
        {meta.accepted.counter, meta.accepted.proposer},
        meta.config
    };
    if (!state.within_jump({ballot.counter, ballot.proposer})) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    ok = state.prepare({ballot.counter, ballot.proposer});
    if (ok) {
        meta.promised = {state.promised().counter, state.promised().proposer};
        _store_witness(id, offset, meta);
    }
    tx.commit();
    return meta;
}

RawstorObjectMeta ObjectStore::sync_accept(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectBallot& ballot,
    const RawstorObjectBallot& next, const RawstorObjectConfig& config, bool& ok
) {
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    Transaction tx(_db);
    RawstorObjectMeta meta = _load_witness(id, offset);
    rawstd::caspaxos::Acceptor<RawstorObjectConfig> state{
        {meta.promised.counter, meta.promised.proposer},
        {meta.accepted.counter, meta.accepted.proposer},
        meta.config
    };
    if (!state.within_jump({ballot.counter, ballot.proposer}) ||
        !state.within_jump({next.counter, next.proposer})) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    ok = state.accept(
        {ballot.counter, ballot.proposer}, config, {next.counter, next.proposer}
    );
    if (ok) {
        meta.promised = {state.promised().counter, state.promised().proposer};
        meta.accepted = {state.accepted().counter, state.accepted().proposer};
        meta.config = state.value();
        _store_witness(id, offset, meta);
    }
    tx.commit();
    return meta;
}

void ObjectStore::remove_witness(const RawstdUUID& id, uint64_t offset) {
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    Stmt stmt(_db, "DELETE FROM witnesses WHERE id=? AND chunk_offset=?");
    stmt.bind_blob(1, id.bytes, sizeof(id.bytes)).bind_int64(2, offset).step();
    if (sqlite3_changes(_db) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
}

/* The owner of the object, nil if there is none. */
static RawstdUUID object_owner(sqlite3* db, const RawstdUUID& id) {
    Stmt select(db, "SELECT account_id FROM objects WHERE id = ?;");
    select.bind_blob(1, id.bytes, sizeof(id.bytes));
    RawstdUUID ret{};
    if (select.step()) {
        select.column_uuid(0, &ret);
    }
    return ret;
}

ObjectStore::Access ObjectStore::authorize(
    const rawtls::SpiffeId* peer, RawstorCommandType command,
    const RawstdUUID& object, const RawstdUUID& account,
    const RawstdUUID& mutation
) {
    Access result{
        std::unique_lock<std::recursive_mutex>(_mutex), RAWSTOR_PERM_ALL, {}
    };
    // The map is being replaced: answered later. A control connection is
    // still acknowledged, so that an OST can connect to register.
    if (_reconstructing && command != RAWSTOR_CMD_SET_OBJECT) {
        RAWSTD_THROW_SYSTEM_ERROR(EAGAIN);
    }
    if (!peer) {
        return result;
    }
    if (peer->type() == rawtls::Type::admin) {
        switch (command) {
        case RAWSTOR_CMD_SET_OBJECT:
        case RAWSTOR_CMD_RESOLVE:
        case RAWSTOR_CMD_LIST:
        case RAWSTOR_CMD_LIST_VERSIONS:
        case RAWSTOR_CMD_OBJ_CREATE:
        case RAWSTOR_CMD_OBJ_RESIZE:
        case RAWSTOR_CMD_OBJ_REMOVE:
        case RAWSTOR_CMD_OBJ_COMMIT_VERSION:
        case RAWSTOR_CMD_OBJ_REMOVE_VERSION:
        case RAWSTOR_CMD_LOCATION_INFO:
        case RAWSTOR_CMD_LIST_ACCOUNTS:
        case RAWSTOR_CMD_LIST_LOCATIONS:
        case RAWSTOR_CMD_ACCOUNT_CREATE:
        case RAWSTOR_CMD_ACCOUNT_REMOVE:
        case RAWSTOR_CMD_OBJ_TRANSFER:
        case RAWSTOR_CMD_SET_OWNER:
        case RAWSTOR_CMD_ALLOCATE:
        case RAWSTOR_CMD_RELEASE:
        case RAWSTOR_CMD_META:
            return result;
        default:
            RAWSTD_THROW_SYSTEM_ERROR(EACCES);
        }
    }
    // An OST connects only to register (authorize_registration()): it gets the
    // control connection acknowledged and nothing else.
    if (peer->type() == rawtls::Type::ost &&
        command == RAWSTOR_CMD_SET_OBJECT && rawstd_uuid_is_nil(&object)) {
        result.permissions = 0;
        return result;
    }
    if (peer->type() != rawtls::Type::account) {
        RAWSTD_THROW_SYSTEM_ERROR(EACCES);
    }
    rawstd_uuid_from_string(&result.account, peer->cert_id().c_str());
    result.permissions = peer->permissions().mask(
        rawstd_uuid_is_nil(&object) ? nullptr : object.bytes
    );
    // SET_OBJECT only acknowledges an MDS control connection. A scoped client
    // can connect for its permitted objects without account-wide permissions.
    if (command == RAWSTOR_CMD_SET_OBJECT && rawstd_uuid_is_nil(&object)) {
        for (const auto& entry : peer->permissions().objects) {
            result.permissions |= entry.second;
        }
    }
    if (!rawstd_uuid_is_nil(&account) &&
        rawstd_uuid_cmp(&account, &result.account)) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    if (rawstd_uuid_is_nil(&object)) {
        switch (command) {
        case RAWSTOR_CMD_RESOLVE:
        case RAWSTOR_CMD_LIST_VERSIONS:
        case RAWSTOR_CMD_OBJ_RESIZE:
        case RAWSTOR_CMD_OBJ_REMOVE:
        case RAWSTOR_CMD_OBJ_COMMIT_VERSION:
        case RAWSTOR_CMD_OBJ_REMOVE_VERSION:
            RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
        default:
            break;
        }
    }
    if (!rawstd_uuid_is_nil(&object)) {
        RawstdUUID owner = object_owner(_db, object);
        bool new_object = false;
        if (command == RAWSTOR_CMD_OBJ_CREATE && rawstd_uuid_is_nil(&owner)) {
            Stmt existing(_db, "SELECT 1 FROM objects WHERE id=?;");
            existing.bind_blob(1, object.bytes, sizeof(object.bytes));
            new_object = !existing.step();
        }
        if (rawstd_uuid_is_nil(&owner) && command == RAWSTOR_CMD_OBJ_REMOVE &&
            !rawstd_uuid_is_nil(&mutation)) {
            Stmt removed(
                _db, "SELECT account_id FROM removed_owners WHERE "
                     "idempotency_key=? AND id=?;"
            );
            removed.bind_blob(1, mutation.bytes, sizeof(mutation.bytes))
                .bind_blob(2, object.bytes, sizeof(object.bytes));
            if (removed.step()) {
                removed.column_uuid(0, &owner);
            }
        }
        if (rawstd_uuid_cmp(&owner, &result.account) && !new_object) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
        }
    }
    uint32_t required = 0;
    switch (command) {
    case RAWSTOR_CMD_SET_OBJECT:
        break;
    case RAWSTOR_CMD_LIST:
        required = RAWSTOR_PERM_READ;
        break;
    case RAWSTOR_CMD_RESOLVE:
        break;
    case RAWSTOR_CMD_LIST_VERSIONS:
        required = RAWSTOR_PERM_READ;
        break;
    case RAWSTOR_CMD_OBJ_CREATE:
    case RAWSTOR_CMD_OBJ_RESIZE:
    case RAWSTOR_CMD_OBJ_REMOVE:
    case RAWSTOR_CMD_OBJ_COMMIT_VERSION:
    case RAWSTOR_CMD_OBJ_REMOVE_VERSION:
        required = RAWSTOR_PERM_MANAGE;
        break;
    default:
        RAWSTD_THROW_SYSTEM_ERROR(EACCES);
    }
    if (!result.permissions || (required && !(result.permissions & required))) {
        RAWSTD_THROW_SYSTEM_ERROR(EACCES);
    }
    return result;
}

ObjectStore::Access ObjectStore::authorize_witness(
    const rawtls::SpiffeId* peer, RawstorCommandType command,
    const RawstdUUID& object, uint64_t offset, const RawstdUUID& account
) {
    Access result{
        std::unique_lock<std::recursive_mutex>(_mutex), RAWSTOR_PERM_ALL, {}
    };
    if (!peer) {
        return result;
    }
    if (peer->type() != rawtls::Type::account) {
        if (!rawtls::provider_member(peer->type(), command)) {
            RAWSTD_THROW_SYSTEM_ERROR(EACCES);
        }
        return result;
    }
    rawstd_uuid_from_string(&result.account, peer->cert_id().c_str());
    result.permissions = peer->permissions().mask(object.bytes);
    uint32_t required = rawtls::member_permission(command);
    if (!required || (result.permissions & required) != required) {
        RAWSTD_THROW_SYSTEM_ERROR(EACCES);
    }
    if (command == RAWSTOR_CMD_ALLOCATE &&
        rawstd_uuid_cmp(&account, &result.account)) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    RawstorObjectMeta meta{};
    try {
        meta = _load_witness(object, offset);
    } catch (const std::system_error& e) {
        if (command == RAWSTOR_CMD_ALLOCATE && e.code().value() == ENOENT) {
            return result;
        }
        throw;
    }
    if (memcmp(
            meta.account_id, result.account.bytes, sizeof(meta.account_id)
        )) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    return result;
}

RawstdUUID ObjectStore::transfer(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& account
) {
    if (rawstd_uuid_is_nil(&account)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    if (replay_mutation(_db, idempotency_key, MutationType::transfer, id)) {
        // Not applied again: the owner is whoever has it now.
        return object_owner(_db, id);
    }
    Transaction tx(_db);
    _require_account(account);
    Stmt update(_db, "UPDATE objects SET account_id=? WHERE id=?");
    update.bind_blob(1, account.bytes, sizeof(account.bytes))
        .bind_blob(2, id.bytes, sizeof(id.bytes))
        .step();
    if (sqlite3_changes(_db) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    record_mutation(_db, idempotency_key, MutationType::transfer, id, {});
    tx.commit();
    return account;
}

void ObjectStore::set_witness_owner(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& account
) {
    if (rawstd_uuid_is_nil(&account)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    Transaction tx(_db);
    RawstorObjectMeta meta = _load_witness(id, offset);
    memcpy(meta.account_id, account.bytes, sizeof(meta.account_id));
    _store_witness(id, offset, meta);
    Stmt update(
        _db, "UPDATE witnesses SET account_id=? WHERE id=? AND chunk_offset=?"
    );
    update.bind_blob(1, account.bytes, sizeof(account.bytes))
        .bind_blob(2, id.bytes, sizeof(id.bytes))
        .bind_int64(3, offset)
        .step();
    tx.commit();
}

std::vector<ChunkEntry> ObjectStore::list_chunks(
    const RawstdUUID& account, RawstdUUID& token, unsigned int limit,
    const std::string& held_by
) {
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    /* The objects an account owns; no account lists them all. */
    const bool all = rawstd_uuid_is_nil(&account);
    /* The entries of the topology at the location, normally one. */
    std::vector<RawstdUUID> holders;
    if (!held_by.empty()) {
        std::string wanted;
        try {
            wanted = rawstd::URI(held_by).canonical();
        } catch (const std::system_error&) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        for (const TopologyOST& ost : _topology->osts()) {
            if (rawstd::URI(ost.location).canonical() == wanted) {
                holders.push_back(ost.id);
            }
        }
        if (holders.empty()) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
        }
    }
    /* The objects with a slot or a version member on one of them. */
    const bool held = !holders.empty();
    if (!held) {
        holders.push_back(RawstdUUID{});
    }
    std::string in = "?";
    for (size_t i = 1; i < holders.size(); ++i) {
        in += ",?";
    }
    const std::string sql =
        "WITH entries AS ("
        "SELECT id,chunk_offset,1 AS type,account_id FROM witnesses "
        "WHERE ?=0 "
        "UNION ALL SELECT id,0,2,account_id FROM objects "
        "WHERE ?=0 OR id IN (SELECT id FROM chunk_map WHERE ost_id IN (" +
        in + ")) OR id IN (SELECT id FROM version_members WHERE ost_id IN (" +
        in +
        "))) "
        "SELECT id,chunk_offset,type,account_id FROM entries WHERE id>? AND "
        "(?=1 OR account_id=?) "
        "ORDER BY id,type DESC,chunk_offset";
    Stmt stmt(_db, sql.c_str());
    int position = 1;
    stmt.bind_int64(position++, held ? 1 : 0);
    stmt.bind_int64(position++, held ? 1 : 0);
    for (int pass = 0; pass < 2; ++pass) {
        for (const RawstdUUID& holder : holders) {
            stmt.bind_blob(position++, holder.bytes, sizeof(holder.bytes));
        }
    }
    RawstdUUID after = token;
    stmt.bind_blob(position++, after.bytes, sizeof(after.bytes));
    stmt.bind_int64(position++, all ? 1 : 0);
    stmt.bind_blob(position++, account.bytes, sizeof(account.bytes));
    std::vector<ChunkEntry> entries;
    RawstdUUID last{};
    unsigned int groups = 0;
    token = {};
    while (stmt.step()) {
        ChunkEntry entry{};
        stmt.column_uuid(0, &entry.id);
        entry.offset = stmt.column_int64(1);
        entry.type = static_cast<RawstorListEntryType>(stmt.column_int64(2));
        stmt.column_uuid(3, &entry.account);
        if (rawstd_uuid_cmp(&entry.id, &last) != 0) {
            if (limit != 0 && groups == limit) {
                token = last;
                break;
            }
            ++groups;
            last = entry.id;
        }
        entries.push_back(entry);
    }
    std::sort(
        entries.begin(), entries.end(),
        [](const ChunkEntry& a, const ChunkEntry& b) {
            int order = rawstd_uuid_cmp(&a.id, &b.id);
            if (order != 0) {
                return order < 0;
            }
            if (a.type != b.type) {
                return a.type > b.type;
            }
            return a.offset < b.offset;
        }
    );
    return entries;
}

std::vector<TopologyOST>
ObjectStore::list_locations(RawstdUUID& token, unsigned int limit) {
    std::lock_guard<std::recursive_mutex> guard(_mutex);
    std::vector<TopologyOST> sorted = _topology->osts();
    std::sort(
        sorted.begin(), sorted.end(),
        [](const TopologyOST& a, const TopologyOST& b) {
            return rawstd_uuid_cmp(&a.id, &b.id) < 0;
        }
    );
    std::vector<TopologyOST> page;
    for (const TopologyOST& ost : sorted) {
        if (rawstd_uuid_cmp(&ost.id, &token) <= 0) {
            continue;
        }
        if (limit != 0 && page.size() == limit) {
            token = page.back().id;
            return page;
        }
        page.push_back(ost);
    }
    token = {};
    return page;
}

std::shared_ptr<const Topology> ObjectStore::topology() {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    return _topology;
}

void ObjectStore::_load_topology() {
    Stmt select(
        _db, "SELECT id, location, weight, roles, domain FROM topology;"
    );
    Topology topology;
    while (select.step()) {
        TopologyOST ost{};
        select.column_uuid(0, &ost.id);
        ost.location = select.column_text(1);
        ost.weight = select.column_int64(2);
        ost.roles = roles_of(select.column_int64(3));
        std::string domain = select.column_text(4);
        if (!domain.empty()) {
            split_domain(domain, ost.path);
        }
        topology.add(ost);
    }
    _topology = std::make_shared<const Topology>(std::move(topology));
}

bool ObjectStore::_alive(const RawstdUUID& id, Clock::time_point now) const {
    if (!rawstd_uuid_is_nil(&_local_witness) &&
        rawstd_uuid_cmp(&id, &_local_witness) == 0) {
        return true;
    }
    auto it = _seen.find(key_of(id));
    return it != _seen.end() && !it->second.leaving &&
           now - it->second.at < _lease;
}

void ObjectStore::authorize_registration(
    const rawtls::SpiffeId* peer, const RawstdUUID& id
) {
    if (!peer) {
        return;
    }
    if (peer->type() != rawtls::Type::ost) {
        RAWSTD_THROW_SYSTEM_ERROR(EACCES);
    }
    RawstdUUID named{};
    if (rawstd_uuid_from_string(&named, peer->cert_id().c_str()) < 0 ||
        rawstd_uuid_cmp(&named, &id) != 0) {
        RawstdUUIDString claimed;
        rawstd_uuid_to_string(&id, &claimed);
        rawstd_error(
            "OST %s registered as %s\n", peer->cert_id().c_str(), claimed
        );
        RAWSTD_THROW_SYSTEM_ERROR(EPERM);
    }
}

void ObjectStore::set_local_witness(const TopologyOST& witness) {
    check_location(witness.location);
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    Stmt upsert(
        _db, "INSERT INTO topology (id, location, weight, roles, domain)"
             " VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET"
             " location = excluded.location, weight = excluded.weight,"
             " roles = excluded.roles, domain = excluded.domain;"
    );
    upsert.bind_blob(1, witness.id.bytes, sizeof(witness.id.bytes))
        .bind_text(2, witness.location)
        .bind_int64(3, witness.weight)
        .bind_int64(4, role_witness)
        .bind_text(5, domain_of(witness))
        .step();
    _local_witness = witness.id;
    _load_topology();
}

void ObjectStore::register_ost(const OstRegistration& registration) {
    TopologyOST ost{};
    ost.id = registration.id;
    if (rawstd_uuid_is_nil(&ost.id)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    check_location(registration.location);
    ost.location = registration.location;
    ost.weight = registration.weight;
    split_domain(registration.domain, ost.path);
    const std::string domain = domain_of(ost);

    std::lock_guard<std::recursive_mutex> lock(_mutex);
    if (!rawstd_uuid_is_nil(&_local_witness) &&
        rawstd_uuid_cmp(&ost.id, &_local_witness) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EEXIST);
    }
    const Clock::time_point now = Clock::now();
    RawstdUUIDString name;
    rawstd_uuid_to_string(&ost.id, &name);

    Stmt select(
        _db, "SELECT location, weight, roles, domain, used, total, members,"
             " members_hash FROM topology WHERE id = ?;"
    );
    select.bind_blob(1, ost.id.bytes, sizeof(ost.id.bytes));
    const bool known = select.step();
    std::string location, old_domain;
    uint64_t weight = 0, roles = 0, used = 0, total = 0, members = 0,
             members_hash = 0;
    if (known) {
        location = select.column_text(0);
        weight = select.column_int64(1);
        roles = select.column_int64(2);
        old_domain = select.column_text(3);
        used = select.column_int64(4);
        total = select.column_int64(5);
        members = select.column_int64(6);
        members_hash = select.column_int64(7);
    }

    // One id, one OST: another process with the same identity is refused for
    // as long as the first one keeps registering.
    if (known && location != ost.location && _alive(ost.id, now)) {
        rawstd_error(
            "OST %s registered at %s while it is registered at %s\n", name,
            printable_location(ost.location).c_str(),
            printable_location(location).c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EEXIST);
    }

    if (!known) {
        rawstd_info(
            "OST %s registered at %s in %s\n", name,
            printable_location(ost.location).c_str(), domain.c_str()
        );
    } else {
        if (location != ost.location) {
            rawstd_info(
                "OST %s moved from %s to %s\n", name,
                printable_location(location).c_str(),
                printable_location(ost.location).c_str()
            );
        }
        // A domain or weight is the OST's own setting. The chunks placed
        // under the old one stay where they are, even where two copies of a
        // chunk now share a domain.
        if (!old_domain.empty() && old_domain != domain) {
            rawstd_warning(
                "OST %s moved from failure domain %s to %s; chunks placed on "
                "it stay where they are\n",
                name, old_domain.c_str(), domain.c_str()
            );
        }
        if (!old_domain.empty() && weight != ost.weight) {
            rawstd_warning(
                "OST %s changed its weight from %llu to %llu\n", name,
                (unsigned long long)weight, (unsigned long long)ost.weight
            );
        }
    }

    const bool changed =
        !known || location != ost.location || weight != ost.weight ||
        roles != (role_data | role_witness) || old_domain != domain;
    const bool resampled =
        registration.sampled && (!known || used != registration.info.used ||
                                 total != registration.info.total ||
                                 members != registration.members.count ||
                                 members_hash != registration.members.hash);
    // A heartbeat that changes nothing writes nothing.
    if (changed || resampled) {
        Transaction tx(_db);
        Stmt upsert(
            _db, "INSERT INTO topology (id, location, weight, roles, domain)"
                 " VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET"
                 " location = excluded.location, weight = excluded.weight,"
                 " roles = excluded.roles, domain = excluded.domain;"
        );
        upsert.bind_blob(1, ost.id.bytes, sizeof(ost.id.bytes))
            .bind_text(2, ost.location)
            .bind_int64(3, ost.weight)
            .bind_int64(4, role_data | role_witness)
            .bind_text(5, domain)
            .step();
        if (resampled) {
            Stmt update(
                _db, "UPDATE topology SET used = ?, total = ?, members = ?,"
                     " members_hash = ? WHERE id = ?;"
            );
            update.bind_int64(1, registration.info.used)
                .bind_int64(2, registration.info.total)
                .bind_int64(3, registration.members.count)
                .bind_int64(4, registration.members.hash)
                .bind_blob(5, ost.id.bytes, sizeof(ost.id.bytes))
                .step();
        }
        tx.commit();
    }
    if (changed) {
        _load_topology();
    }

    // Not with a map that is being replaced.
    if (registration.sampled && !registration.leaving && !_reconstructing) {
        _check_members(ost, registration.members, now);
    }
    const bool was_alive = _alive(ost.id, now);
    _seen[key_of(ost.id)] = Seen{now, registration.leaving};
    if (registration.leaving) {
        rawstd_info("OST %s is leaving\n", name);
    } else if (!was_alive && known) {
        rawstd_info("OST %s is available\n", name);
    }
    _sweep(now, registration.leaving);
}

/*
 * Drops the entries of the OSTs that are unavailable and hold nothing: they
 * take no chunks and no chunk refers to them, and an OST that comes back
 * registers again. One that has not registered since the MDS started gets a
 * lease to do so first. Runs at most once a lease, or at once for an OST that
 * has just left.
 */
void ObjectStore::_sweep(Clock::time_point now, bool force) {
    if (!force && now - _last_sweep < _lease) {
        return;
    }
    _last_sweep = now;
    Stmt held(
        _db, "SELECT 1 FROM chunk_map WHERE ost_id = ?"
             " UNION ALL SELECT 1 FROM version_members WHERE ost_id = ?"
             " LIMIT 1;"
    );
    std::vector<RawstdUUID> gone;
    for (const TopologyOST& ost : _topology->osts()) {
        if (_alive(ost.id, now)) {
            continue;
        }
        auto seen = _seen.find(key_of(ost.id));
        if (seen == _seen.end() && now - _started < _lease) {
            continue;
        }
        held.reset();
        held.bind_blob(1, ost.id.bytes, sizeof(ost.id.bytes))
            .bind_blob(2, ost.id.bytes, sizeof(ost.id.bytes));
        if (held.step()) {
            continue;
        }
        gone.push_back(ost.id);
    }
    if (gone.empty()) {
        return;
    }
    Transaction tx(_db);
    Stmt del(_db, "DELETE FROM topology WHERE id = ?;");
    for (const RawstdUUID& id : gone) {
        del.reset();
        del.bind_blob(1, id.bytes, sizeof(id.bytes)).step();
    }
    tx.commit();
    for (const RawstdUUID& id : gone) {
        _seen.erase(key_of(id));
        RawstdUUIDString name;
        rawstd_uuid_to_string(&id, &name);
        rawstd_info("OST %s left the topology\n", name);
    }
    _load_topology();
}

bool ObjectStore::backend_available(const RawstdUUID& id) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    return _alive(id, Clock::now());
}

std::vector<TopologyOST> ObjectStore::available_osts() {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    std::vector<TopologyOST> ret;
    const Clock::time_point now = Clock::now();
    for (const TopologyOST& ost : _topology->osts()) {
        if (rawstd_uuid_cmp(&ost.id, &_local_witness) != 0 &&
            _alive(ost.id, now)) {
            ret.push_back(ost);
        }
    }
    return ret;
}

void ObjectStore::set_reconstructing(bool reconstructing) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    _reconstructing = reconstructing;
}

std::vector<Member> ObjectStore::members_on(const RawstdUUID& ost) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    return _members_on(ost);
}

std::vector<Member> ObjectStore::_members_on(const RawstdUUID& ost) {
    Stmt select(
        _db, "SELECT c.id, c.logical_index * o.chunk_size FROM chunk_map c"
             " JOIN objects o ON o.id = c.id WHERE c.ost_id = ?;"
    );
    select.bind_blob(1, ost.bytes, sizeof(ost.bytes));
    std::vector<Member> ret;
    while (select.step()) {
        Member member{};
        select.column_uuid(0, &member.id);
        member.offset = select.column_int64(1);
        ret.push_back(member);
    }
    return ret;
}

void ObjectStore::set_disagreement_listener(
    std::function<void(const TopologyOST&)> listener
) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    _on_disagreement = std::move(listener);
}

void ObjectStore::_slots_changed(const std::vector<RawstdUUID>& osts) {
    for (const RawstdUUID& id : osts) {
        _map_changed.insert(key_of(id));
    }
}

/*
 * The map's digest is computed only when the OST's or the map's has changed
 * since the last comparison, so a heartbeat costs nothing here. A
 * disagreement is given a lease to go away before it is reported: between a
 * create's reply and the client creating the chunks, the map places members
 * the OST does not have yet, until its next sample.
 */
void ObjectStore::_check_members(
    const TopologyOST& ost, const MemberDigest& reported, Clock::time_point now
) {
    const std::string key = key_of(ost.id);
    Digests& digests = _digests[key];
    const bool changed = _map_changed.erase(key) != 0;
    if (!digests.checked || changed || digests.reported != reported) {
        MemberDigest expected;
        for (const Member& member : _members_on(ost.id)) {
            expected.add(member.id, member.offset);
        }
        const bool same = digests.checked && digests.reported == reported &&
                          digests.expected == expected;
        digests.reported = reported;
        digests.expected = expected;
        digests.checked = true;
        if (reported == expected) {
            if (digests.reported_disagreement) {
                RawstdUUIDString name;
                rawstd_uuid_to_string(&ost.id, &name);
                rawstd_info("OST %s agrees with the map again\n", name);
            }
            digests.disagreeing.reset();
            digests.reported_disagreement = false;
        } else if (!same) {
            digests.disagreeing = now;
            digests.reported_disagreement = false;
        }
    }
    if (digests.disagreeing && !digests.reported_disagreement &&
        now - *digests.disagreeing >= _lease) {
        digests.reported_disagreement = true;
        RawstdUUIDString name;
        rawstd_uuid_to_string(&ost.id, &name);
        rawstd_warning(
            "OST %s disagrees with the map: it holds %llu member(s), the "
            "map places %llu on it; listing it\n",
            name, (unsigned long long)digests.reported.count,
            (unsigned long long)digests.expected.count
        );
        if (_on_disagreement) {
            _on_disagreement(ost);
        }
    }
}

RawstorLocationInfo ObjectStore::info() {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    RawstorLocationInfo result{};
    // A witness holds no data: the MDS's own counts no storage.
    Stmt select(_db, "SELECT used, total FROM topology WHERE roles & ?;");
    select.bind_int64(1, role_data);
    while (select.step()) {
        uint64_t used = select.column_int64(0);
        uint64_t total = select.column_int64(1);
        if (used > UINT64_MAX - result.used ||
            total > UINT64_MAX - result.total) {
            RAWSTD_THROW_SYSTEM_ERROR(EOVERFLOW);
        }
        result.used += used;
        result.total += total;
    }
    return result;
}

Topology ObjectStore::_available_topology() {
    const Clock::time_point now = Clock::now();
    std::vector<RawstdUUID> ids;
    for (const TopologyOST& ost : _topology->osts()) {
        if (_alive(ost.id, now)) {
            ids.push_back(ost.id);
        }
    }
    return _topology->select(ids);
}

ObjectDescriptor ObjectStore::create(
    const RawstdUUID& account, const RawstdUUID& idempotency_key,
    const RawstdUUID& id, uint64_t logical_size, uint64_t chunk_size,
    const PlacementPolicy& policy
) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    validate_geometry(logical_size, chunk_size);

    if (replay_mutation(_db, idempotency_key, MutationType::create, id)) {
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
    ret.map_version = 1;

    uint64_t nchunks = nchunks_of(logical_size, chunk_size);

    /* The owner is a registered account, or none. */
    _require_account(account);

    /* Hard-fails on an unsatisfiable topology before anything lands. */
    Topology available = _available_topology();
    place_chunk(available, ret.id, 0, policy);

    Transaction tx(_db);

    {
        Stmt insert(
            _db, "INSERT INTO objects"
                 " (id, account_id, logical_size, chunk_size, width,"
                 " failure_domain, stripe_width, placement_seed, map_version,"
                 " created_at)"
                 " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
        );
        insert.bind_blob(1, ret.id.bytes, sizeof(ret.id.bytes))
            .bind_blob(2, account.bytes, sizeof(account.bytes))
            .bind_int64(3, logical_size)
            .bind_int64(4, chunk_size)
            .bind_int64(5, policy.width)
            .bind_int64(6, static_cast<uint64_t>(policy.failure_domain))
            .bind_int64(7, policy.stripe_width)
            .bind_int64(8, policy.seed)
            .bind_int64(9, ret.map_version)
            .bind_int64(10, static_cast<uint64_t>(time(nullptr)))
            .step();
    }

    std::vector<RawstdUUID> touched = insert_chunks(
        _db, available, ret.id, 0, nchunks, chunk_size, ret.policy
    );

    record_mutation(_db, idempotency_key, MutationType::create, id, {});

    tx.commit();
    _slots_changed(touched);

    return ret;
}

ObjectMap
ObjectStore::open(const RawstdUUID& id, const RawstdUUID& version_id) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    if (!rawstd_uuid_is_nil(&version_id)) {
        return _open_version(id, version_id);
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
        const auto width = ret.descriptor.policy.width;
        const auto expected = width + (width % 2 == 0 ? 1u : 0u);
        if (ret.chunks[index].size() != expected) {
            rawstd_warning(
                "MDS store: chunk %zu has %zu of %u slots\n", index,
                ret.chunks[index].size(), expected
            );
        }
    }

    return ret;
}

ResizeResult ObjectStore::resize(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t new_size
) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    if (std::optional<std::vector<unsigned char>> recorded =
            replay_mutation(_db, idempotency_key, MutationType::resize, id)) {
        ResultReader r(*recorded);
        ResizeResult ret{};
        ret.map_version = r.get<uint64_t>();
        ret.old_nchunks = r.get<uint64_t>();
        // Not recorded: the owner may have changed since.
        ret.account = object_owner(_db, id);
        return ret;
    }

    ObjectDescriptor descriptor = _descriptor(id);

    validate_geometry(new_size, descriptor.chunk_size);

    /* Grow-only in v1: shrink interacts with GC and versions. */
    if (new_size < descriptor.logical_size) {
        rawstd_error("Object shrink is not supported\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    uint64_t old_chunks =
        nchunks_of(descriptor.logical_size, descriptor.chunk_size);
    uint64_t new_chunks = nchunks_of(new_size, descriptor.chunk_size);
    uint64_t map_version = descriptor.map_version + 1;

    Transaction tx(_db);

    {
        Stmt update(
            _db, "UPDATE objects SET logical_size = ?, map_version = ?"
                 " WHERE id = ?;"
        );
        update.bind_int64(1, new_size)
            .bind_int64(2, map_version)
            .bind_blob(3, id.bytes, sizeof(id.bytes))
            .step();
    }

    std::vector<RawstdUUID> touched = insert_chunks(
        _db, _available_topology(), id, old_chunks, new_chunks,
        descriptor.chunk_size, descriptor.policy
    );

    record_mutation(
        _db, idempotency_key, MutationType::resize, id,
        ResultWriter().put(map_version).put(old_chunks).data()
    );

    tx.commit();
    _slots_changed(touched);

    return ResizeResult{
        .map_version = map_version,
        .old_nchunks = old_chunks,
        .account = object_owner(_db, id)
    };
}

void ObjectStore::reconstruct(const std::vector<ScanRecord>& records) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    // Every comparison was with the map this replaces.
    _digests.clear();
    _map_changed.clear();
    struct Chunk {
        /* Scan order becomes the slot order. */
        std::vector<RawstdUUID> ost_ids;
    };
    struct Object {
        uint64_t chunk_size;
        unsigned width;
        RawstdUUID account;
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
            memcpy(o.account.bytes, r.meta.account_id, sizeof(o.account.bytes));
            if (o.chunk_size == 0 || (o.chunk_size & (o.chunk_size - 1)) != 0 ||
                o.width == 0) {
                rawstd_error(
                    "reconstruct: %s: malformed stored identity\n", obj_str
                );
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
        } else if (o.chunk_size != r.meta.spec.chunk_size ||
                   o.width != r.meta.spec.width ||
                   memcmp(
                       o.account.bytes, r.meta.account_id,
                       sizeof(o.account.bytes)
                   ) != 0) {
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
        _db, "DELETE FROM version_members;"
             "DELETE FROM versions;"
             "DELETE FROM objects;"
    );

    for (const auto& [key, o] : objects) {
        RawstdUUID id;
        memcpy(id.bytes, key.data(), sizeof(id.bytes));
        RawstdUUIDString id_str;
        rawstd_uuid_to_string(&id, &id_str);

        /* An account the scan found as an owner is registered again. */
        if (!rawstd_uuid_is_nil(&o.account)) {
            Stmt account_insert(
                _db, "INSERT OR IGNORE INTO accounts (id, created_at) "
                     "VALUES (?, ?);"
            );
            account_insert
                .bind_blob(1, o.account.bytes, sizeof(o.account.bytes))
                .bind_int64(2, static_cast<uint64_t>(time(nullptr)))
                .step();
        }

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
                     " (id, account_id, logical_size, chunk_size, width,"
                     " failure_domain, stripe_width, placement_seed,"
                     " map_version, created_at)"
                     " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
            );
            insert.bind_blob(1, id.bytes, sizeof(id.bytes))
                .bind_blob(2, o.account.bytes, sizeof(o.account.bytes))
                .bind_int64(3, logical_size)
                .bind_int64(4, o.chunk_size)
                .bind_int64(5, o.width)
                .bind_int64(
                    6, static_cast<uint64_t>(rawstor::mdsserver::Level::OST)
                )
                .bind_int64(7, STRIPE_ALL)
                .bind_int64(8, 0)
                .bind_int64(9, 1)
                .bind_int64(10, static_cast<uint64_t>(time(nullptr)))
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
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    if (std::optional<std::vector<unsigned char>> recorded =
            replay_mutation(_db, idempotency_key, MutationType::remove, id)) {
        return decode_map(*recorded);
    }

    Transaction tx(_db);

    {
        /* An object with versions must not silently disappear. */
        Stmt busy(_db, "SELECT version_id FROM versions WHERE id = ? LIMIT 1;");
        busy.bind_blob(1, id.bytes, sizeof(id.bytes));
        if (busy.step()) {
            rawstd_error("Object has versions; remove them first\n");
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }
    }

    // ENOENT if there is no such object.
    ObjectMap ret = _open_live(id);
    RawstdUUID owner = object_owner(_db, id);

    {
        Stmt del(_db, "DELETE FROM objects WHERE id = ?;");
        del.bind_blob(1, id.bytes, sizeof(id.bytes)).step();
    }

    record_mutation(
        _db, idempotency_key, MutationType::remove, id, encode_map(ret)
    );
    if (!rawstd_uuid_is_nil(&idempotency_key)) {
        Stmt saved(
            _db, "INSERT INTO removed_owners(idempotency_key,id,account_id) "
                 "VALUES(?,?,?);"
        );
        saved.bind_blob(1, idempotency_key.bytes, sizeof(idempotency_key.bytes))
            .bind_blob(2, id.bytes, sizeof(id.bytes))
            .bind_blob(3, owner.bytes, sizeof(owner.bytes))
            .step();
    }

    tx.commit();
    std::vector<RawstdUUID> touched;
    for (const auto& chunk : ret.chunks) {
        for (const PlacementSlot& slot : chunk) {
            touched.push_back(slot.ost_id);
        }
    }
    _slots_changed(touched);

    return ret;
}

std::vector<RawstdUUID> ObjectStore::list_versions(const RawstdUUID& id) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    _descriptor(id);

    Stmt select(
        _db, "SELECT version_id FROM versions WHERE id = ?"
             " ORDER BY version_id;"
    );
    select.bind_blob(1, id.bytes, sizeof(id.bytes));
    std::vector<RawstdUUID> ret;
    while (select.step()) {
        RawstdUUID version_id;
        select.column_uuid(0, &version_id);
        ret.push_back(version_id);
    }
    return ret;
}

ObjectMap
ObjectStore::_open_version(const RawstdUUID& id, const RawstdUUID& version_id) {
    ObjectMap ret{};
    ret.descriptor = _descriptor(id);

    {
        Stmt select(
            _db, "SELECT logical_size FROM versions"
                 " WHERE id = ? AND version_id = ?;"
        );
        select.bind_blob(1, id.bytes, sizeof(id.bytes))
            .bind_blob(2, version_id.bytes, sizeof(version_id.bytes));
        if (!select.step()) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
        }
        /* The size the object had when the version was taken. */
        ret.descriptor.logical_size = select.column_int64(0);
    }

    uint64_t nchunks =
        nchunks_of(ret.descriptor.logical_size, ret.descriptor.chunk_size);
    ret.chunks.resize(nchunks);

    Stmt select(
        _db, "SELECT logical_index, ost_id FROM version_members"
             " WHERE id = ? AND version_id = ?"
             " ORDER BY logical_index, ost_id;"
    );
    select.bind_blob(1, id.bytes, sizeof(id.bytes))
        .bind_blob(2, version_id.bytes, sizeof(version_id.bytes));

    uint64_t prev_index = 0;
    uint8_t slot = 0;
    while (select.step()) {
        uint64_t index = select.column_int64(0);
        if (index >= nchunks) {
            rawstd_error("MDS store: version member out of bounds\n");
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

    /* commit_version() never registers a version with an uncovered chunk. */
    for (size_t index = 0; index < ret.chunks.size(); ++index) {
        if (ret.chunks[index].empty()) {
            rawstd_error("MDS store: version is missing a chunk\n");
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
    }

    return ret;
}

uint64_t ObjectStore::commit_version(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& version_id, const std::vector<VersionMember>& members
) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    if (std::optional<std::vector<unsigned char>> recorded = replay_mutation(
            _db, idempotency_key, MutationType::commit_version, id
        )) {
        return ResultReader(*recorded).get<uint64_t>();
    }

    ObjectDescriptor descriptor = _descriptor(id);
    uint64_t nchunks =
        nchunks_of(descriptor.logical_size, descriptor.chunk_size);

    if (rawstd_uuid_is_nil(&version_id)) {
        rawstd_error("A nil version_id is the live version\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    /*
     * Every chunk must be covered: an unreadable version is never
     * registered. (A degraded object legitimately registers fewer members
     * per chunk than the policy width — recorded, not repaired.)
     */
    std::vector<bool> covered(nchunks, false);
    for (const VersionMember& m : members) {
        if (m.logical_index >= nchunks) {
            rawstd_error("Version member out of object bounds\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        covered[m.logical_index] = true;
    }
    for (bool c : covered) {
        if (!c) {
            rawstd_error("Version does not cover every chunk\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }

    uint64_t map_version = descriptor.map_version + 1;

    Transaction tx(_db);

    {
        Stmt insert(
            _db, "INSERT INTO versions"
                 " (id, version_id, logical_size, created_at)"
                 " VALUES (?, ?, ?, ?);"
        );
        insert.bind_blob(1, id.bytes, sizeof(id.bytes))
            .bind_blob(2, version_id.bytes, sizeof(version_id.bytes))
            .bind_int64(3, descriptor.logical_size)
            .bind_int64(4, static_cast<uint64_t>(time(nullptr)))
            .step();
    }

    {
        Stmt insert(
            _db, "INSERT INTO version_members"
                 " (id, version_id, logical_index, ost_id)"
                 " VALUES (?, ?, ?, ?);"
        );
        for (const VersionMember& m : members) {
            insert.reset();
            insert.bind_blob(1, id.bytes, sizeof(id.bytes))
                .bind_blob(2, version_id.bytes, sizeof(version_id.bytes))
                .bind_int64(3, m.logical_index)
                .bind_blob(4, m.ost_id.bytes, sizeof(m.ost_id.bytes))
                .step();
        }
    }

    {
        Stmt update(_db, "UPDATE objects SET map_version = ? WHERE id = ?;");
        update.bind_int64(1, map_version)
            .bind_blob(2, id.bytes, sizeof(id.bytes))
            .step();
    }

    record_mutation(
        _db, idempotency_key, MutationType::commit_version, id,
        ResultWriter().put(map_version).data()
    );

    tx.commit();

    return map_version;
}

std::vector<VersionMember> ObjectStore::remove_version(
    const RawstdUUID& idempotency_key, const RawstdUUID& id,
    const RawstdUUID& version_id
) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    std::vector<VersionMember> ret;
    if (std::optional<std::vector<unsigned char>> recorded = replay_mutation(
            _db, idempotency_key, MutationType::remove_version, id
        )) {
        ResultReader r(*recorded);
        ret.resize(r.get<uint64_t>());
        for (VersionMember& m : ret) {
            m.logical_index = r.get<uint64_t>();
            m.ost_id = r.get<RawstdUUID>();
        }
        return ret;
    }

    Transaction tx(_db);

    {
        Stmt select(
            _db, "SELECT logical_index, ost_id FROM version_members"
                 " WHERE id = ? AND version_id = ?"
                 " ORDER BY logical_index, ost_id;"
        );
        select.bind_blob(1, id.bytes, sizeof(id.bytes))
            .bind_blob(2, version_id.bytes, sizeof(version_id.bytes));
        while (select.step()) {
            VersionMember m{};
            m.logical_index = select.column_int64(0);
            select.column_uuid(1, &m.ost_id);
            ret.push_back(m);
        }
    }

    {
        Stmt del(
            _db, "DELETE FROM versions"
                 " WHERE id = ? AND version_id = ?;"
        );
        del.bind_blob(1, id.bytes, sizeof(id.bytes))
            .bind_blob(2, version_id.bytes, sizeof(version_id.bytes))
            .step();
    }

    if (sqlite3_changes(_db) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    ResultWriter w;
    w.put(static_cast<uint64_t>(ret.size()));
    for (const VersionMember& m : ret) {
        w.put(m.logical_index).put(m.ost_id);
    }
    record_mutation(
        _db, idempotency_key, MutationType::remove_version, id, w.data()
    );

    tx.commit();

    return ret;
}

void ObjectStore::create_account(
    const RawstdUUID& idempotency_key, const RawstdUUID& account
) {
    if (rawstd_uuid_is_nil(&account)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    /* The registry's own mutations are recorded under the account they concern.
     */
    if (replay_mutation(
            _db, idempotency_key, MutationType::create_account, account
        )) {
        // Registered, then removed again by a later request: this retry
        // registers it afresh, as a retried object creation does.
        Stmt exists(_db, "SELECT 1 FROM accounts WHERE id = ?;");
        exists.bind_blob(1, account.bytes, sizeof(account.bytes));
        if (exists.step()) {
            return;
        }
    }

    Transaction tx(_db);
    Stmt insert(_db, "INSERT INTO accounts (id, created_at) VALUES (?, ?);");
    insert.bind_blob(1, account.bytes, sizeof(account.bytes))
        .bind_int64(2, static_cast<uint64_t>(time(nullptr)))
        .step();
    record_mutation(
        _db, idempotency_key, MutationType::create_account, account, {}
    );
    tx.commit();
}

void ObjectStore::remove_account(
    const RawstdUUID& idempotency_key, const RawstdUUID& account
) {
    RawstdUUID default_account;
    rawstd_uuid_from_string(&default_account, RAWSTOR_DEFAULT_ACCOUNT);
    if (rawstd_uuid_cmp(&account, &default_account) == 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EPERM);
    }
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    if (replay_mutation(
            _db, idempotency_key, MutationType::remove_account, account
        )) {
        return;
    }

    Transaction tx(_db);
    Stmt exists(_db, "SELECT 1 FROM accounts WHERE id = ?;");
    exists.bind_blob(1, account.bytes, sizeof(account.bytes));
    if (!exists.step()) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    /* An account that owns an object is not empty. */
    {
        Stmt busy(_db, "SELECT 1 FROM objects WHERE account_id = ? LIMIT 1;");
        busy.bind_blob(1, account.bytes, sizeof(account.bytes));
        if (busy.step()) {
            rawstd_error("The account still owns objects\n");
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }
    }

    {
        Stmt del(_db, "DELETE FROM accounts WHERE id = ?;");
        del.bind_blob(1, account.bytes, sizeof(account.bytes)).step();
    }
    record_mutation(
        _db, idempotency_key, MutationType::remove_account, account, {}
    );
    tx.commit();
}

std::vector<RawstdUUID>
ObjectStore::list_accounts(RawstdUUID& token, unsigned int limit) {
    std::lock_guard<std::recursive_mutex> lock(_mutex);
    Stmt select(_db, "SELECT id FROM accounts WHERE id>? ORDER BY id;");
    // The statement reads `after` until it is done; `token` is rewritten.
    const RawstdUUID after = token;
    select.bind_blob(1, after.bytes, sizeof(after.bytes));
    std::vector<RawstdUUID> ret;
    token = {};
    while (select.step()) {
        if (limit != 0 && ret.size() == limit) {
            token = ret.back();
            break;
        }
        RawstdUUID account;
        select.column_uuid(0, &account);
        ret.push_back(account);
    }
    return ret;
}

} // namespace mdsserver
} // namespace rawstor
