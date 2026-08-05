#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/object.h>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <filesystem>
#include <sstream>
#include <string>

namespace {

void write_legacy_object(
    const std::filesystem::path& location_path, const std::string& uuid,
    uint64_t size
) {
    std::filesystem::create_directories(location_path);

    std::filesystem::path dat_path = location_path / (uuid + ".dat");
    int fd = ::open(dat_path.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    ASSERT_EQ(::ftruncate(fd, size), 0);
    ASSERT_EQ(::close(fd), 0);

    std::filesystem::path spec_path = location_path / (uuid + ".spec");
    RawstorObjectSpec spec{.size = size};
    fd = ::open(spec_path.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    ASSERT_EQ(::write(fd, &spec, sizeof(spec)), (ssize_t)sizeof(spec));
    ASSERT_EQ(::close(fd), 0);
}

TEST(FileLegacyMigrationTest, spec_migrates_and_cleans_up) {
    std::filesystem::path location_path =
        std::filesystem::temp_directory_path() / "test_file_legacy_spec";
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    rawstd::URI location_uri(oss.str());
    std::string uuid = "00000000-0000-7000-8000-000000000010";
    std::string target = rawstd::URI(location_uri, uuid).str();

    write_legacy_object(location_path, uuid, 1ull << 20);

    RawstorObjectSpec read_spec = {};
    int res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    EXPECT_TRUE(std::filesystem::exists(location_path / uuid));
    EXPECT_FALSE(std::filesystem::exists(location_path / (uuid + ".dat")));
    EXPECT_FALSE(std::filesystem::exists(location_path / (uuid + ".spec")));

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLegacyMigrationTest, remove_handles_unmigrated_legacy_object) {
    std::filesystem::path location_path =
        std::filesystem::temp_directory_path() / "test_file_legacy_remove";
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    rawstd::URI location_uri(oss.str());
    std::string uuid = "00000000-0000-7000-8000-000000000011";
    std::string target = rawstd::URI(location_uri, uuid).str();

    write_legacy_object(location_path, uuid, 1ull << 20);

    int res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);

    EXPECT_FALSE(std::filesystem::exists(location_path / uuid));
    EXPECT_FALSE(std::filesystem::exists(location_path / (uuid + ".dat")));
    EXPECT_FALSE(std::filesystem::exists(location_path / (uuid + ".spec")));
}

TEST(FileLegacyMigrationTest, interrupted_migration_leftover_spec_cleaned_up) {
    std::filesystem::path location_path =
        std::filesystem::temp_directory_path() / "test_file_legacy_interrupted";
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    rawstd::URI location_uri(oss.str());
    std::string uuid = "00000000-0000-7000-8000-000000000012";
    std::string target = rawstd::URI(location_uri, uuid).str();

    // Simulate a migration that renamed the .dat file but crashed before
    // removing the leftover .spec.
    write_legacy_object(location_path, uuid, 1ull << 20);
    std::filesystem::rename(
        location_path / (uuid + ".dat"), location_path / uuid
    );
    ASSERT_TRUE(std::filesystem::exists(location_path / uuid));
    ASSERT_TRUE(std::filesystem::exists(location_path / (uuid + ".spec")));

    RawstorObjectSpec read_spec = {};
    int res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    EXPECT_FALSE(std::filesystem::exists(location_path / (uuid + ".spec")));

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLegacyMigrationTest, list_sees_legacy_and_new_objects_once) {
    std::filesystem::path location_path =
        std::filesystem::temp_directory_path() / "test_file_legacy_list";
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    rawstd::URI location_uri(oss.str());
    std::string location = location_uri.str();
    std::string uuid_new = "00000000-0000-7000-8000-000000000013";
    std::string uuid_legacy = "00000000-0000-7000-8000-000000000014";
    std::string target_new = rawstd::URI(location_uri, uuid_new).str();

    RawstorObjectSpec spec{.size = 1ull << 20};
    int res = rawstor_object_create(target_new.c_str(), &spec);
    EXPECT_EQ(res, 0);

    write_legacy_object(location_path, uuid_legacy, 2ull << 20);

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor_object_list(location.c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(2));
        rawstor_string_list_delete(targets);
    }

    res = rawstor_object_remove(target_new.c_str());
    EXPECT_EQ(res, 0);
    res = rawstor_object_remove(
        rawstd::URI(location_uri, uuid_legacy).str().c_str()
    );
    EXPECT_EQ(res, 0);
}

} // unnamed namespace
