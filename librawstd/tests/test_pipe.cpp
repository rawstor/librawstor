#include "rawstd/pipe.hpp"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <utility>

namespace {

TEST(PipeTest, constructs_valid_distinct_fds) {
    rawstd::Pipe p(rawstd::Pipe::Mode::Blocking);

    EXPECT_GE(p.read_fd(), 0);
    EXPECT_GE(p.write_fd(), 0);
    EXPECT_NE(p.read_fd(), p.write_fd());
}

TEST(PipeTest, write_read_round_trip) {
    rawstd::Pipe p(rawstd::Pipe::Mode::Blocking);

    char out = 'x';
    ASSERT_EQ(write(p.write_fd(), &out, 1), 1);

    char in = 0;
    ASSERT_EQ(read(p.read_fd(), &in, 1), 1);
    EXPECT_EQ(in, 'x');
}

TEST(PipeTest, blocking_mode_has_no_nonblock_flag) {
    rawstd::Pipe p(rawstd::Pipe::Mode::Blocking);

    EXPECT_EQ(fcntl(p.read_fd(), F_GETFL) & O_NONBLOCK, 0);
    EXPECT_EQ(fcntl(p.write_fd(), F_GETFL) & O_NONBLOCK, 0);
}

TEST(PipeTest, nonblocking_mode_reports_eagain_with_nothing_to_read) {
    rawstd::Pipe p(rawstd::Pipe::Mode::NonBlocking);

    char buf;
    errno = 0;
    ssize_t res = read(p.read_fd(), &buf, 1);

    EXPECT_EQ(res, -1);
    EXPECT_EQ(errno, EAGAIN);
    errno = 0;
}

TEST(PipeTest, move_construct_transfers_ownership) {
    rawstd::Pipe p(rawstd::Pipe::Mode::Blocking);
    int read_fd = p.read_fd();
    int write_fd = p.write_fd();

    rawstd::Pipe moved(std::move(p));

    EXPECT_EQ(moved.read_fd(), read_fd);
    EXPECT_EQ(moved.write_fd(), write_fd);
    // A moved-from Pipe holds neither end any more, so its destructor
    // (already run once `p` goes out of scope below) won't double-close
    // what `moved` now owns.
    EXPECT_EQ(p.read_fd(), -1);
    EXPECT_EQ(p.write_fd(), -1);
}

TEST(PipeTest, move_assign_closes_previous_and_takes_over) {
    rawstd::Pipe a(rawstd::Pipe::Mode::Blocking);
    rawstd::Pipe b(rawstd::Pipe::Mode::Blocking);
    int b_read_fd = b.read_fd();
    int b_write_fd = b.write_fd();

    a = std::move(b);

    EXPECT_EQ(a.read_fd(), b_read_fd);
    EXPECT_EQ(a.write_fd(), b_write_fd);
    EXPECT_EQ(b.read_fd(), -1);
    EXPECT_EQ(b.write_fd(), -1);
}

TEST(PipeTest, release_gives_up_ownership_without_closing) {
    int released_read_fd;
    int released_write_fd;
    {
        rawstd::Pipe p(rawstd::Pipe::Mode::Blocking);
        released_read_fd = p.release_read();
        released_write_fd = p.release_write();

        EXPECT_EQ(p.read_fd(), -1);
        EXPECT_EQ(p.write_fd(), -1);
        // ~Pipe() runs here with both ends already released -- if it
        // closed them anyway, the round trip below would fail.
    }

    char out = 'y';
    ASSERT_EQ(write(released_write_fd, &out, 1), 1);
    char in = 0;
    ASSERT_EQ(read(released_read_fd, &in, 1), 1);
    EXPECT_EQ(in, 'y');

    close(released_read_fd);
    close(released_write_fd);
}

} // namespace
