#include <mds/topology.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>

#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>

#include <cerrno>
#include <cstring>

namespace {

// Splits a root-first path, "[[[dc/]row/]rack/]server", into `out`'s
// dc, row, rack, server slots. Only the server is required; the path may
// start at any level, and a level left out stays empty, so every entry
// that leaves it out shares that one implicit domain.
void split_path(const std::string& s, std::string (&out)[4]) {
    std::string parts[4];
    size_t n = 0;
    size_t begin = 0;
    while (true) {
        size_t end = s.find('/', begin);
        std::string part = s.substr(
            begin, end == std::string::npos ? std::string::npos : end - begin
        );
        if (part.empty() || n == 4) {
            rawstd_error("Malformed topology path: %s\n", s.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        parts[n++] = part;
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    for (size_t i = 0; i < 4; ++i) {
        out[i] = i < 4 - n ? std::string() : parts[i - (4 - n)];
    }
}

} // namespace

namespace rawstor {
namespace mdsserver {

Level level_of(unsigned value) {
    switch (value) {
    case static_cast<unsigned>(Level::OST):
    case static_cast<unsigned>(Level::Server):
    case static_cast<unsigned>(Level::Rack):
    case static_cast<unsigned>(Level::Row):
    case static_cast<unsigned>(Level::DC):
        return static_cast<Level>(value);
    default:
        rawstd_error("Unknown failure domain level: %u\n", value);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
}

std::string TopologyOST::domain(Level level) const {
    // How many leading path components (dc, row, rack, server) name a
    // domain at `level`; an OST adds its own id below its server.
    unsigned depth = 0;
    switch (level) {
    case Level::DC:
        depth = 1;
        break;
    case Level::Row:
        depth = 2;
        break;
    case Level::Rack:
        depth = 3;
        break;
    case Level::Server:
    case Level::OST:
        depth = 4;
        break;
    }
    if (depth == 0) {
        level_of(static_cast<unsigned>(level)); // throws
    }

    std::string ret = path[0];
    for (unsigned i = 1; i < depth; ++i) {
        ret += '/';
        ret += path[i];
    }
    if (level == Level::OST) {
        RawstdUUIDString s;
        rawstd_uuid_to_string(&id, &s);
        ret += '/';
        ret += s;
    }
    return ret;
}

Topology Topology::select(const std::vector<RawstdUUID>& ids) const {
    std::unordered_set<std::string> selected;
    selected.reserve(ids.size());
    for (const auto& id : ids) {
        selected.emplace(
            reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes)
        );
    }
    Topology result;
    for (const auto& ost : _osts) {
        if (selected.contains(
                std::string(
                    reinterpret_cast<const char*>(ost.id.bytes),
                    sizeof(ost.id.bytes)
                )
            )) {
            result._osts.push_back(ost);
        }
    }
    return result;
}

Topology Topology::parse(std::istream& in) {
    Topology ret;

    std::string line;
    size_t lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;

        size_t comment = line.find('#');
        if (comment != std::string::npos) {
            line.resize(comment);
        }

        std::istringstream tokens(line);
        std::string id;
        if (!(tokens >> id)) {
            continue; /* blank */
        }

        std::string location, path;
        uint64_t weight = 0;
        if (!(tokens >> location >> weight >> path)) {
            rawstd_error("Topology line %zu: malformed entry\n", lineno);
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        std::string extra;
        if (tokens >> extra) {
            rawstd_error(
                "Topology line %zu: trailing tokens: %s\n", lineno,
                extra.c_str()
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        TopologyOST ost{};
        int res = rawstd_uuid_from_string(&ost.id, id.c_str());
        if (res < 0) {
            rawstd_error(
                "Topology line %zu: malformed ost id: %s\n", lineno, id.c_str()
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        // One URI per entry: an entry is one placement slot, i.e. one
        // member with one vote in the mirror quorum (docs/mds.md).
        if (rawstd::URI::uriv(location.c_str()).size() != 1) {
            rawstd_error(
                "Topology line %zu: expected a single location URI: %s\n",
                lineno, location.c_str()
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        ost.location = location;
        ost.weight = weight;
        split_path(path, ost.path);

        ret.add(ost);
    }

    return ret;
}

Topology Topology::parse_file(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) {
        rawstd_error("Failed to open topology config: %s\n", path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    return parse(in);
}

void Topology::add(const TopologyOST& ost) {
    for (const TopologyOST& existing : _osts) {
        if (memcmp(existing.id.bytes, ost.id.bytes, sizeof(ost.id.bytes)) ==
            0) {
            rawstd_error("Duplicate ost id in topology\n");
            RAWSTD_THROW_SYSTEM_ERROR(EEXIST);
        }
    }

    _osts.push_back(ost);
}

} // namespace mdsserver
} // namespace rawstor
