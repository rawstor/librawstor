#include "blkdev_meta.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstring>

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
    uint64_t vol_hi = 0;
    uint64_t vol_lo = 0;
    for (unsigned i = 0; i < 8; ++i) {
        vol_hi = (vol_hi << 8) | meta.volume_id[i];
        vol_lo = (vol_lo << 8) | meta.volume_id[8 + i];
    }

    char buf[512];
    snprintf(
        buf, sizeof(buf),
        "state=%u:epoch=%" PRIx64 ":sync_id=%" PRIx64 ":h0=%" PRIx64
        ":h1=%" PRIx64 ":h2=%" PRIx64 ":h3=%" PRIx64 ":kind=%u:w=%u"
        ":volhi=%" PRIx64 ":vollo=%" PRIx64 ":idx=%" PRIx64 ":csz=%" PRIx64
        ":snap=%" PRIx64,
        meta.state, meta.epoch, meta.sync_id, meta.sync_id_history[0],
        meta.sync_id_history[1], meta.sync_id_history[2],
        meta.sync_id_history[3], meta.member_kind, meta.width, vol_hi, vol_lo,
        meta.logical_index, meta.chunk_size, meta.snap_version
    );
    return std::string(buf);
}

bool blkdev_meta_decode(const std::string& value, RawstorObjectMeta* out) {
    RawstorObjectMeta meta{};
    unsigned int state = 0;
    unsigned int kind = 0;
    unsigned int width = 0;
    uint64_t vol_hi = 0;
    uint64_t vol_lo = 0;

    int n = sscanf(
        trim(value).c_str(),
        "state=%u:epoch=%" SCNx64 ":sync_id=%" SCNx64 ":h0=%" SCNx64
        ":h1=%" SCNx64 ":h2=%" SCNx64 ":h3=%" SCNx64 ":kind=%u:w=%u"
        ":volhi=%" SCNx64 ":vollo=%" SCNx64 ":idx=%" SCNx64 ":csz=%" SCNx64
        ":snap=%" SCNx64,
        &state, &meta.epoch, &meta.sync_id, &meta.sync_id_history[0],
        &meta.sync_id_history[1], &meta.sync_id_history[2],
        &meta.sync_id_history[3], &kind, &width, &vol_hi, &vol_lo,
        &meta.logical_index, &meta.chunk_size, &meta.snap_version
    );
    if (n != 14) {
        return false;
    }

    meta.state = state;
    meta.member_kind = static_cast<uint8_t>(kind);
    meta.width = static_cast<uint8_t>(width);
    for (unsigned i = 0; i < 8; ++i) {
        meta.volume_id[i] = static_cast<uint8_t>(vol_hi >> (8 * (7 - i)));
        meta.volume_id[8 + i] = static_cast<uint8_t>(vol_lo >> (8 * (7 - i)));
    }
    *out = meta;
    return true;
}

void blkdev_meta_merge_identity(
    RawstorObjectMeta* meta, const RawstorObjectMeta& stored
) {
    meta->member_kind = stored.member_kind;
    meta->width = stored.width;
    memcpy(meta->volume_id, stored.volume_id, sizeof(meta->volume_id));
    meta->logical_index = stored.logical_index;
    meta->chunk_size = stored.chunk_size;
    meta->snap_version = stored.snap_version;
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
