#include "rawstorstd/uri.hpp"

#include <gtest/gtest.h>

namespace {

TEST(URITest, empty) {
    rawstor::URI uri("");

    EXPECT_EQ(uri.str(), "");
    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.userinfo(), "");
    EXPECT_EQ(uri.username(), "");
    EXPECT_EQ(uri.password(), "");
    EXPECT_EQ(uri.authority(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.hostname(), "");
    EXPECT_EQ(uri.port(), 0u);
    EXPECT_EQ(uri.path().str(), "");
    EXPECT_EQ(uri.path().dirname(), "/");
    EXPECT_EQ(uri.path().filename(), "");
}

TEST(URITest, http) {
    rawstor::URI uri("http://user:password@example.com:80/foo");

    EXPECT_EQ(uri.str(), "http://user:password@example.com:80/foo");
    EXPECT_EQ(uri.scheme(), "http");
    EXPECT_EQ(uri.userinfo(), "user:password");
    EXPECT_EQ(uri.username(), "user");
    EXPECT_EQ(uri.password(), "password");
    EXPECT_EQ(uri.authority(), "user:password@example.com:80");
    EXPECT_EQ(uri.host(), "example.com:80");
    EXPECT_EQ(uri.hostname(), "example.com");
    EXPECT_EQ(uri.port(), 80u);
    EXPECT_EQ(uri.path().str(), "/foo");
    EXPECT_EQ(uri.path().dirname(), "/");
    EXPECT_EQ(uri.path().filename(), "foo");
}

TEST(URITest, file) {
    rawstor::URI uri("file:///tmp/foo");

    EXPECT_EQ(uri.str(), "file:///tmp/foo");
    EXPECT_EQ(uri.scheme(), "file");
    EXPECT_EQ(uri.userinfo(), "");
    EXPECT_EQ(uri.username(), "");
    EXPECT_EQ(uri.password(), "");
    EXPECT_EQ(uri.authority(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.hostname(), "");
    EXPECT_EQ(uri.port(), 0u);
    EXPECT_EQ(uri.path().str(), "/tmp/foo");
    EXPECT_EQ(uri.path().dirname(), "/tmp");
    EXPECT_EQ(uri.path().filename(), "foo");
}

TEST(URITest, empty_path) {
    rawstor::URI uri("ost://127.0.0.1:8080");

    EXPECT_EQ(uri.str(), "ost://127.0.0.1:8080");
    EXPECT_EQ(uri.scheme(), "ost");
    EXPECT_EQ(uri.userinfo(), "");
    EXPECT_EQ(uri.username(), "");
    EXPECT_EQ(uri.password(), "");
    EXPECT_EQ(uri.authority(), "127.0.0.1:8080");
    EXPECT_EQ(uri.host(), "127.0.0.1:8080");
    EXPECT_EQ(uri.hostname(), "127.0.0.1");
    EXPECT_EQ(uri.port(), 8080u);
    EXPECT_EQ(uri.path().str(), "");
    EXPECT_EQ(uri.path().dirname(), "/");
    EXPECT_EQ(uri.path().filename(), "");
}

TEST(URITest, with_uuid) {
    rawstor::URI uri("file:///tmp/objects/uuid");

    EXPECT_EQ(uri.str(), "file:///tmp/objects/uuid");
    EXPECT_EQ(uri.scheme(), "file");
    EXPECT_EQ(uri.userinfo(), "");
    EXPECT_EQ(uri.username(), "");
    EXPECT_EQ(uri.password(), "");
    EXPECT_EQ(uri.authority(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.hostname(), "");
    EXPECT_EQ(uri.port(), 0u);
    EXPECT_EQ(uri.path().str(), "/tmp/objects/uuid");
    EXPECT_EQ(uri.path().dirname(), "/tmp/objects");
    EXPECT_EQ(uri.path().filename(), "uuid");
}

TEST(URITest, without_uuid_with_slash) {
    rawstor::URI uri("file:///tmp/objects/");

    EXPECT_EQ(uri.str(), "file:///tmp/objects/");
    EXPECT_EQ(uri.scheme(), "file");
    EXPECT_EQ(uri.userinfo(), "");
    EXPECT_EQ(uri.username(), "");
    EXPECT_EQ(uri.password(), "");
    EXPECT_EQ(uri.authority(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.hostname(), "");
    EXPECT_EQ(uri.port(), 0u);
    EXPECT_EQ(uri.path().str(), "/tmp/objects/");
    EXPECT_EQ(uri.path().dirname(), "/tmp/objects");
    EXPECT_EQ(uri.path().filename(), "");
}

TEST(URITest, without_uuid_without_slash) {
    rawstor::URI uri("file:///tmp/objects");

    EXPECT_EQ(uri.str(), "file:///tmp/objects");
    EXPECT_EQ(uri.scheme(), "file");
    EXPECT_EQ(uri.userinfo(), "");
    EXPECT_EQ(uri.username(), "");
    EXPECT_EQ(uri.password(), "");
    EXPECT_EQ(uri.authority(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.hostname(), "");
    EXPECT_EQ(uri.port(), 0u);
    EXPECT_EQ(uri.path().str(), "/tmp/objects");
    EXPECT_EQ(uri.path().dirname(), "/tmp");
    EXPECT_EQ(uri.path().filename(), "objects");
}

TEST(URITest, parent) {
    rawstor::URI uri("http://user:password@example.com:80/foo/bar/span/");
    EXPECT_EQ(uri.str(), "http://user:password@example.com:80/foo/bar/span/");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user:password@example.com:80/foo/bar/span");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user:password@example.com:80/foo/bar");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user:password@example.com:80/foo");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user:password@example.com:80/");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user:password@example.com:80/");
}

TEST(URITest, child) {
    rawstor::URI parent_with_slash("http://user:password@example.com:80/");
    rawstor::URI child_with_slash(parent_with_slash, "foo");

    EXPECT_EQ(
        child_with_slash.str(), "http://user:password@example.com:80/foo"
    );

    rawstor::URI parent_without_slash("http://user:password@example.com:80");
    rawstor::URI child_without_slash(parent_without_slash, "foo");

    EXPECT_EQ(
        child_without_slash.str(), "http://user:password@example.com:80/foo"
    );
}

TEST(URIsTest, basics) {
    {
        std::vector<rawstor::URI> uris = rawstor::URI::uriv("a,b,c");
        EXPECT_EQ(uris.size(), (size_t)3);
        EXPECT_EQ(uris[0].str(), "a");
        EXPECT_EQ(uris[1].str(), "b");
        EXPECT_EQ(uris[2].str(), "c");
    }

    {
        std::vector<rawstor::URI> uris = rawstor::URI::uriv("a\\,b,c");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "a\\,b");
        EXPECT_EQ(uris[1].str(), "c");
    }

    {
        std::vector<rawstor::URI> uris = rawstor::URI::uriv("a,b,");
        EXPECT_EQ(uris.size(), (size_t)3);
        EXPECT_EQ(uris[0].str(), "a");
        EXPECT_EQ(uris[1].str(), "b");
        EXPECT_EQ(uris[2].str(), "");
    }

    {
        std::vector<rawstor::URI> uris = rawstor::URI::uriv("");
        EXPECT_EQ(uris.size(), (size_t)1);
        EXPECT_EQ(uris[0].str(), "");
    }

    {
        std::vector<rawstor::URI> uris = rawstor::URI::uriv(",");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "");
        EXPECT_EQ(uris[1].str(), "");
    }

    {
        std::vector<rawstor::URI> uris = rawstor::URI::uriv(",a");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "");
        EXPECT_EQ(uris[1].str(), "a");
    }

    {
        std::vector<rawstor::URI> uris = rawstor::URI::uriv("a,");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "a");
        EXPECT_EQ(uris[1].str(), "");
    }

    {
        std::vector<rawstor::URI> uris = rawstor::URI::uriv("\\,a");
        EXPECT_EQ(uris.size(), (size_t)1);
        EXPECT_EQ(uris[0].str(), "\\,a");
    }
}

} // namespace
