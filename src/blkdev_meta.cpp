#include "blkdev_meta.hpp"

#include <cinttypes>
#include <cstdio>

namespace {

std::string trim(const std::string& s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return "";
    }
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

} // namespace

namespace rawstor {

std::string blkdev_meta_encode(const RawstorObjectMeta& meta) {
    char buf[256];
    snprintf(
        buf, sizeof(buf),
        "state=%u:epoch=%" PRIx64 ":sync_id=%" PRIx64 ":h0=%" PRIx64
        ":h1=%" PRIx64 ":h2=%" PRIx64 ":h3=%" PRIx64,
        meta.state, meta.epoch, meta.sync_id, meta.sync_id_history[0],
        meta.sync_id_history[1], meta.sync_id_history[2],
        meta.sync_id_history[3]
    );
    return std::string(buf);
}

bool blkdev_meta_decode(const std::string& value, RawstorObjectMeta* out) {
    RawstorObjectMeta meta{};
    unsigned int state = 0;

    int n = sscanf(
        trim(value).c_str(),
        "state=%u:epoch=%" SCNx64 ":sync_id=%" SCNx64 ":h0=%" SCNx64
        ":h1=%" SCNx64 ":h2=%" SCNx64 ":h3=%" SCNx64,
        &state, &meta.epoch, &meta.sync_id, &meta.sync_id_history[0],
        &meta.sync_id_history[1], &meta.sync_id_history[2],
        &meta.sync_id_history[3]
    );
    if (n != 7) {
        return false;
    }

    meta.state = state;
    *out = meta;
    return true;
}

std::string
blkdev_find_tag(const std::string& tag_list, const std::string& prefix) {
    std::string trimmed = trim(tag_list);

    size_t pos = 0;
    while (pos <= trimmed.size()) {
        size_t comma = trimmed.find(',', pos);
        size_t len =
            comma == std::string::npos ? std::string::npos : comma - pos;
        std::string tag = trim(trimmed.substr(pos, len));

        if (tag.compare(0, prefix.size(), prefix) == 0) {
            return tag.substr(prefix.size());
        }

        if (comma == std::string::npos) {
            break;
        }
        pos = comma + 1;
    }

    return "";
}

} // namespace rawstor
