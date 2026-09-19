#include "topology.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <fstream>
#include <sstream>
#include <string>

#include <cerrno>
#include <cstring>

namespace {

void split_path(const std::string& s, std::string (&out)[3]) {
    size_t begin = 0;
    for (int i = 0; i < 3; ++i) {
        size_t end = s.find('/', begin);
        if ((end == std::string::npos) != (i == 2)) {
            rawstd_error("Malformed topology path: %s\n", s.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        out[i] = s.substr(
            begin, end == std::string::npos ? std::string::npos : end - begin
        );
        if (out[i].empty()) {
            rawstd_error("Malformed topology path: %s\n", s.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
        begin = end + 1;
    }
}

} // namespace

namespace rawstor {
namespace mds {

std::string TopologyOST::domain(Level level) const {
    std::string ret = path[0];
    for (unsigned i = 1; i <= static_cast<unsigned>(level) && i < 3; ++i) {
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
        std::string kind;
        if (!(tokens >> kind)) {
            continue; /* blank */
        }

        if (kind != "ost") {
            rawstd_error(
                "Topology line %zu: unknown entry: %s\n", lineno, kind.c_str()
            );
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        std::string id, address, path;
        uint64_t weight = 0;
        if (!(tokens >> id >> address >> weight >> path)) {
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
        ost.address = address;
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

} // namespace mds
} // namespace rawstor
