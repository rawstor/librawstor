#ifndef RAWSTOR_TESTS_DISK_RECORD_HPP
#define RAWSTOR_TESTS_DISK_RECORD_HPP

#include "blk_backend.hpp"

#include <rawstor/target.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace rawstor {
namespace tests {

// A file:// copy's record as it is on disk right now (blk::Backend::
// meta_encode()), read without running a queue. An unreadable record
// comes back zero-filled.
inline blk::Backend::Record disk_record(const std::filesystem::path& meta) {
    std::ifstream f(meta, std::ios::binary);
    std::string raw(
        (std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()
    );
    blk::Backend::Record record{};
    blk::Backend::ChunkIdentity identity{};
    try {
        blk::Backend::meta_decode(raw.c_str(), &record, &identity);
    } catch (const std::system_error&) {
        record = blk::Backend::Record{};
    }
    return record;
}

// Rewrites a file:// copy's own state on disk, as a copy left by an
// earlier process would hold it: the state is the copy's own, never set
// through the API (docs/mirroring.md, "DIRTY, CLEAN and LOST").
inline void disk_set_state(
    const std::filesystem::path& meta, RawstorObjectSyncStateValue state
) {
    std::string raw;
    {
        std::ifstream f(meta, std::ios::binary);
        raw.assign(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>()
        );
    }
    blk::Backend::Record record{};
    blk::Backend::ChunkIdentity identity{};
    blk::Backend::meta_decode(raw.c_str(), &record, &identity);
    record.state = state;
    std::string encoded = blk::Backend::meta_encode(record, identity);
    std::string padded(raw.size(), '\0');
    padded.replace(0, encoded.size(), encoded);
    std::ofstream f(meta, std::ios::binary | std::ios::trunc);
    f.write(padded.data(), static_cast<std::streamsize>(padded.size()));
}

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_DISK_RECORD_HPP
