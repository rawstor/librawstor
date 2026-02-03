#include "rawstorstd/iovec.h"

#include <gtest/gtest.h>

#include <sys/uio.h>

#include <list>
#include <string>
#include <vector>

#include <cstdlib>
#include <cstring>

namespace {

class IOVecTest : public testing::Test {
private:
    std::list<std::string> _iov_src_data;
    std::vector<iovec> _iov_src;

protected:
    iovec* _iov;
    unsigned int _niov;

    IOVecTest() : _niov(3) {
        for (unsigned int i = 0; i < _niov; ++i) {
            _iov_src_data.push_back("1234567890");
            _iov_src.push_back(
                {.iov_base = _iov_src_data.back().data(),
                 .iov_len = _iov_src_data.back().size()}
            );
        }
        _iov = _iov_src.data();
    }
};

TEST_F(IOVecTest, discard_front_unaligned) {
    iovec* iov_at = _iov;
    unsigned int niov_at = _niov;

    size_t size = rawstor_iovec_discard_front(&iov_at, &niov_at, 12);

    EXPECT_EQ(niov_at, 2u);
    EXPECT_EQ(
        strncmp(static_cast<const char*>(iov_at[0].iov_base), "34567890", 8), 0
    );
    EXPECT_EQ(iov_at[0].iov_len, (size_t)8);
    EXPECT_EQ(size, (size_t)12);
}

TEST_F(IOVecTest, discard_front_aligned) {
    iovec* iov_at = _iov;
    unsigned int niov_at = _niov;

    size_t size = rawstor_iovec_discard_front(&iov_at, &niov_at, 10);

    EXPECT_EQ(niov_at, 2u);
    EXPECT_EQ(
        strncmp(static_cast<const char*>(iov_at[0].iov_base), "1234567890", 10),
        0
    );
    EXPECT_EQ(iov_at[0].iov_len, (size_t)10);
    EXPECT_EQ(size, (size_t)10);
}

TEST_F(IOVecTest, discard_front_all) {
    iovec* iov_at = _iov;
    unsigned int niov_at = _niov;

    size_t size = rawstor_iovec_discard_front(&iov_at, &niov_at, 30);

    EXPECT_EQ(niov_at, 0u);
    EXPECT_EQ(size, (size_t)30);
}

TEST_F(IOVecTest, discard_front_overflow) {
    iovec* iov_at = _iov;
    unsigned int niov_at = _niov;

    size_t size = rawstor_iovec_discard_front(&iov_at, &niov_at, 35);

    EXPECT_EQ(niov_at, 0u);
    EXPECT_EQ(size, (size_t)30);
}

TEST_F(IOVecTest, discard_back_unaligned) {
    iovec* iov_at = _iov;
    unsigned int niov_at = _niov;

    size_t size = rawstor_iovec_discard_back(&iov_at, &niov_at, 12);

    EXPECT_EQ(niov_at, 2u);
    EXPECT_EQ(
        strncmp(static_cast<const char*>(iov_at[1].iov_base), "12345678", 8), 0
    );
    EXPECT_EQ(iov_at[1].iov_len, (size_t)8);
    EXPECT_EQ(size, (size_t)12);
}

TEST_F(IOVecTest, discard_back_aligned) {
    iovec* iov_at = _iov;
    unsigned int niov_at = _niov;

    size_t size = rawstor_iovec_discard_back(&iov_at, &niov_at, 10);

    EXPECT_EQ(niov_at, 2u);
    EXPECT_EQ(
        strncmp(static_cast<const char*>(iov_at[1].iov_base), "1234567890", 10),
        0
    );
    EXPECT_EQ(iov_at[1].iov_len, (size_t)10);
    EXPECT_EQ(size, (size_t)10);
}

TEST_F(IOVecTest, discard_back_all) {
    iovec* iov_at = _iov;
    unsigned int niov_at = _niov;

    size_t size = rawstor_iovec_discard_back(&iov_at, &niov_at, 30);

    EXPECT_EQ(niov_at, 0u);
    EXPECT_EQ(size, (size_t)30);
}

TEST_F(IOVecTest, discard_back_overflow) {
    iovec* iov_at = _iov;
    unsigned int niov_at = _niov;

    size_t size = rawstor_iovec_discard_back(&iov_at, &niov_at, 35);

    EXPECT_EQ(niov_at, 0u);
    EXPECT_EQ(size, (size_t)30);
}

TEST_F(IOVecTest, from_buf_unaligned) {
    char buf[] = "abcdefghijkl";
    size_t size = rawstor_iovec_from_buf(_iov, _niov, 0, buf, sizeof(buf) - 1);

    EXPECT_EQ(size, (size_t)12);
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[0].iov_base), "abcdefghij",
            _iov[0].iov_len
        ),
        0
    );
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[1].iov_base), "kl34567890",
            _iov[1].iov_len
        ),
        0
    );
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[2].iov_base), "1234567890",
            _iov[2].iov_len
        ),
        0
    );
}

TEST_F(IOVecTest, from_buf_aligned) {
    char buf[] = "abcdefghij";
    size_t size = rawstor_iovec_from_buf(_iov, _niov, 0, buf, sizeof(buf) - 1);

    EXPECT_EQ(size, (size_t)10);
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[0].iov_base), "abcdefghij",
            _iov[0].iov_len
        ),
        0
    );
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[1].iov_base), "1234567890",
            _iov[1].iov_len
        ),
        0
    );
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[2].iov_base), "1234567890",
            _iov[2].iov_len
        ),
        0
    );
}

TEST_F(IOVecTest, from_buf_all) {
    char buf[] = "abcdefghijklmnopqrstuvwxyzabcd";
    size_t size = rawstor_iovec_from_buf(_iov, _niov, 0, buf, sizeof(buf) - 1);

    EXPECT_EQ(size, (size_t)30);
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[0].iov_base), "abcdefghij",
            _iov[0].iov_len
        ),
        0
    );
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[1].iov_base), "klmnopqrst",
            _iov[1].iov_len
        ),
        0
    );
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[2].iov_base), "uvwxyzabcd",
            _iov[2].iov_len
        ),
        0
    );
}

TEST_F(IOVecTest, from_buf_overflow) {
    char buf[] = "abcdefghijklmnopqrstuvwxyzabcdefghi";
    size_t size = rawstor_iovec_from_buf(_iov, _niov, 0, buf, sizeof(buf) - 1);

    EXPECT_EQ(size, (size_t)30);
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[0].iov_base), "abcdefghij",
            _iov[0].iov_len
        ),
        0
    );
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[1].iov_base), "klmnopqrst",
            _iov[1].iov_len
        ),
        0
    );
    EXPECT_EQ(
        strncmp(
            static_cast<const char*>(_iov[2].iov_base), "uvwxyzabcd",
            _iov[2].iov_len
        ),
        0
    );
}

TEST_F(IOVecTest, to_buf_unaligned) {
    char buf[12];
    size_t size = rawstor_iovec_to_buf(_iov, _niov, 0, buf, sizeof(buf));

    EXPECT_EQ(size, (size_t)12);
    EXPECT_EQ(strncmp(buf, "123456789012", size), 0);

    size = rawstor_iovec_to_buf(_iov, _niov, 3, buf, sizeof(buf));

    EXPECT_EQ(size, (size_t)12);
    EXPECT_EQ(strncmp(buf, "456789012345", size), 0);
}

TEST_F(IOVecTest, to_buf_aligned) {
    char buf[10];
    size_t size = rawstor_iovec_to_buf(_iov, _niov, 0, buf, sizeof(buf));

    EXPECT_EQ(size, (size_t)10);
    EXPECT_EQ(strncmp(buf, "1234567890", size), 0);

    size = rawstor_iovec_to_buf(_iov, _niov, 10, buf, sizeof(buf));

    EXPECT_EQ(size, (size_t)10);
    EXPECT_EQ(strncmp(buf, "1234567890", size), 0);
}

TEST_F(IOVecTest, to_buf_all) {
    char buf[30];
    size_t size = rawstor_iovec_to_buf(_iov, _niov, 0, buf, sizeof(buf));

    EXPECT_EQ(size, (size_t)30);
    EXPECT_EQ(strncmp(buf, "123456789012345678901234567890", size), 0);

    size = rawstor_iovec_to_buf(_iov, _niov, 3, buf, sizeof(buf) - 3);

    EXPECT_EQ(size, (size_t)27);
    EXPECT_EQ(strncmp(buf, "456789012345678901234567890", size), 0);
}

TEST_F(IOVecTest, to_buf_overflow) {
    char buf[35];
    size_t size = rawstor_iovec_to_buf(_iov, _niov, 0, buf, sizeof(buf));

    EXPECT_EQ(size, (size_t)30);
    EXPECT_EQ(strncmp(buf, "123456789012345678901234567890", size), 0);

    size = rawstor_iovec_to_buf(_iov, _niov, 3, buf, sizeof(buf));

    EXPECT_EQ(size, (size_t)27);
    EXPECT_EQ(strncmp(buf, "456789012345678901234567890", size), 0);
}

TEST_F(IOVecTest, to_iovec) {
    std::vector<std::string> iov_dst_data;
    std::vector<iovec> iov_dst;

    for (unsigned int i = 0; i < 3; ++i) {
        iov_dst_data.push_back(std::string(4, ' '));
    }

    for (unsigned int i = 0; i < 3; ++i) {
        iov_dst.push_back(
            {.iov_base = iov_dst_data[i].data(),
             .iov_len = iov_dst_data[i].size()}
        );
    }

    size_t size =
        rawstor_iovec_to_iovec(_iov, _niov, 3, iov_dst.data(), iov_dst.size());

    EXPECT_EQ(size, (size_t)12);
    EXPECT_EQ(strncmp(iov_dst_data[0].data(), "4567", 4), 0);
    EXPECT_EQ(strncmp(iov_dst_data[1].data(), "8901", 4), 0);
    EXPECT_EQ(strncmp(iov_dst_data[2].data(), "2345", 4), 0);

    size =
        rawstor_iovec_to_iovec(_iov, _niov, 20, iov_dst.data(), iov_dst.size());

    EXPECT_EQ(size, (size_t)10);
    EXPECT_EQ(strncmp(iov_dst_data[0].data(), "1234", 4), 0);
    EXPECT_EQ(strncmp(iov_dst_data[1].data(), "5678", 4), 0);
    EXPECT_EQ(strncmp(iov_dst_data[2].data(), "90", 2), 0);
}

TEST_F(IOVecTest, size) {
    EXPECT_EQ(rawstor_iovec_size(_iov, _niov), (size_t)30);
}

} // unnamed namespace
