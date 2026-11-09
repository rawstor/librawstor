#include <vhost/dirty_log.hpp>

#include <gtest/gtest.h>

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <system_error>
#include <vector>

namespace {

using rawstor::vhost::DirtyLog;

class DirtyLogTest : public ::testing::Test {
protected:
    static constexpr uint64_t log_size = 64;
    static constexpr uint64_t file_offset = 4096;

    FILE* _file = nullptr;
    int _fd = -1;

    void SetUp() override {
        _file = tmpfile();
        ASSERT_NE(_file, nullptr);
        _fd = fileno(_file);
        ASSERT_EQ(ftruncate(_fd, file_offset + log_size), 0);
    }

    void TearDown() override {
        if (_file != nullptr) {
            fclose(_file);
        }
    }

    std::vector<uint8_t> bitmap() {
        std::vector<uint8_t> data(log_size);
        EXPECT_EQ(
            pread(_fd, data.data(), data.size(), file_offset),
            static_cast<ssize_t>(data.size())
        );
        return data;
    }
};

TEST_F(DirtyLogTest, marks_single_page) {
    DirtyLog log(_fd, log_size, file_offset);

    log.mark(3 * DirtyLog::page_size + 100, 8);

    std::vector<uint8_t> data = bitmap();
    EXPECT_EQ(data[0], 1u << 3);
    for (size_t i = 1; i < data.size(); ++i) {
        EXPECT_EQ(data[i], 0) << i;
    }
}

TEST_F(DirtyLogTest, marks_every_page_of_a_range) {
    DirtyLog log(_fd, log_size, file_offset);

    // Page 7 is the last bit of byte 0, pages 8 and 9 the first two of
    // byte 1.
    log.mark(7 * DirtyLog::page_size + DirtyLog::page_size - 1, 2);
    log.mark(8 * DirtyLog::page_size, DirtyLog::page_size + 1);

    std::vector<uint8_t> data = bitmap();
    EXPECT_EQ(data[0], 1u << 7);
    EXPECT_EQ(data[1], 0b11);
}

TEST_F(DirtyLogTest, keeps_existing_bits) {
    DirtyLog log(_fd, log_size, file_offset);

    log.mark(0, 1);
    log.mark(DirtyLog::page_size, 1);

    EXPECT_EQ(bitmap()[0], 0b11);
}

TEST_F(DirtyLogTest, ignores_empty_range) {
    DirtyLog log(_fd, log_size, file_offset);

    log.mark(0, 0);

    EXPECT_EQ(bitmap()[0], 0);
}

TEST_F(DirtyLogTest, ignores_pages_beyond_the_bitmap) {
    DirtyLog log(_fd, log_size, file_offset);

    log.mark(log_size * 8 * DirtyLog::page_size, DirtyLog::page_size);
    log.mark((log_size * 8 - 1) * DirtyLog::page_size, 3 * DirtyLog::page_size);

    EXPECT_EQ(bitmap()[log_size - 1], 1u << 7);
}

TEST_F(DirtyLogTest, maps_unaligned_offset) {
    DirtyLog log(_fd, log_size - 16, file_offset + 16);

    log.mark(0, 1);

    EXPECT_EQ(bitmap()[16], 1);
}

TEST_F(DirtyLogTest, rejects_empty_log) {
    EXPECT_THROW(DirtyLog(_fd, 0, 0), std::system_error);
}

} // namespace
