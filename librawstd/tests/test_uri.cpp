#include "rawstd/uri.hpp"

#include <gtest/gtest.h>

namespace {

TEST(URITest, empty) {
    rawstd::URI uri("");

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

TEST(URITest, userinfo_without_password) {
    rawstd::URI uri("ost://tenant@example.com:7777/foo");

    EXPECT_EQ(uri.str(), "ost://tenant@example.com:7777/foo");
    EXPECT_EQ(uri.scheme(), "ost");
    EXPECT_EQ(uri.userinfo(), "tenant");
    EXPECT_EQ(uri.username(), "tenant");
    EXPECT_EQ(uri.password(), "");
    EXPECT_EQ(uri.authority(), "tenant@example.com:7777");
    EXPECT_EQ(uri.host(), "example.com:7777");
    EXPECT_EQ(uri.hostname(), "example.com");
    EXPECT_EQ(uri.port(), 7777u);
    EXPECT_EQ(uri.path().str(), "/foo");
}

TEST(URITest, userinfo_without_host) {
    rawstd::URI uri("file://tenant@/var/lib/rawstor");

    EXPECT_EQ(uri.userinfo(), "tenant");
    EXPECT_EQ(uri.hostname(), "");
    EXPECT_EQ(uri.path().str(), "/var/lib/rawstor");
}

TEST(URITest, str_leaves_the_password_out) {
    rawstd::URI uri("ost://user:secret@10.0.0.1:7777/obj");
    EXPECT_EQ(uri.str(), "ost://user@10.0.0.1:7777/obj");
    EXPECT_EQ(uri.password(), "secret");
    EXPECT_EQ(
        rawstd::URI::uris({uri, uri}),
        "ost://user@10.0.0.1:7777/obj,ost://user@10.0.0.1:7777/obj"
    );

    // A child keeps what its parent has, and prints without it too.
    rawstd::URI child(uri, "0");
    EXPECT_EQ(child.str(), "ost://user@10.0.0.1:7777/obj/0");
    EXPECT_EQ(child.password(), "secret");

    // A password with no user name goes with its '@'.
    EXPECT_EQ(
        rawstd::URI("ost://:secret@10.0.0.1:7777").str(), "ost://10.0.0.1:7777"
    );

    // Nothing to leave out.
    EXPECT_EQ(rawstd::URI("ost://user@10.0.0.1").str(), "ost://user@10.0.0.1");
    EXPECT_EQ(rawstd::URI("file:///var/a@b:c").str(), "file:///var/a@b:c");
}

TEST(URITest, http) {
    rawstd::URI uri("http://user:password@example.com:80/foo");

    // Printing never discloses the password; reading it still does.
    EXPECT_EQ(uri.str(), "http://user@example.com:80/foo");
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
    rawstd::URI uri("file:///tmp/foo");

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
    rawstd::URI uri("ost://127.0.0.1:7777");

    EXPECT_EQ(uri.str(), "ost://127.0.0.1:7777");
    EXPECT_EQ(uri.scheme(), "ost");
    EXPECT_EQ(uri.userinfo(), "");
    EXPECT_EQ(uri.username(), "");
    EXPECT_EQ(uri.password(), "");
    EXPECT_EQ(uri.authority(), "127.0.0.1:7777");
    EXPECT_EQ(uri.host(), "127.0.0.1:7777");
    EXPECT_EQ(uri.hostname(), "127.0.0.1");
    EXPECT_EQ(uri.port(), 7777u);
    EXPECT_EQ(uri.path().str(), "");
    EXPECT_EQ(uri.path().dirname(), "/");
    EXPECT_EQ(uri.path().filename(), "");
}

TEST(URITest, with_uuid) {
    rawstd::URI uri("file:///tmp/objects/uuid");

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
    rawstd::URI uri("file:///tmp/objects/");

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
    rawstd::URI uri("file:///tmp/objects");

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
    rawstd::URI uri("http://user:password@example.com:80/foo/bar/span/");
    EXPECT_EQ(uri.str(), "http://user@example.com:80/foo/bar/span/");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user@example.com:80/foo/bar/span");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user@example.com:80/foo/bar");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user@example.com:80/foo");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user@example.com:80/");

    uri = uri.parent();
    EXPECT_EQ(uri.str(), "http://user@example.com:80/");
}

TEST(URITest, child) {
    rawstd::URI parent_with_slash("http://user:password@example.com:80/");
    rawstd::URI child_with_slash(parent_with_slash, "foo");

    EXPECT_EQ(child_with_slash.str(), "http://user@example.com:80/foo");

    rawstd::URI parent_without_slash("http://user:password@example.com:80");
    rawstd::URI child_without_slash(parent_without_slash, "foo");

    EXPECT_EQ(child_without_slash.str(), "http://user@example.com:80/foo");
}

TEST(URIsTest, basics) {
    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv("a,b,c");
        EXPECT_EQ(uris.size(), (size_t)3);
        EXPECT_EQ(uris[0].str(), "a");
        EXPECT_EQ(uris[1].str(), "b");
        EXPECT_EQ(uris[2].str(), "c");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, "a,b,c");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv("a\\,b,c");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "a,b");
        EXPECT_EQ(uris[1].str(), "c");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, "a\\,b,c");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv("a,b,");
        EXPECT_EQ(uris.size(), (size_t)3);
        EXPECT_EQ(uris[0].str(), "a");
        EXPECT_EQ(uris[1].str(), "b");
        EXPECT_EQ(uris[2].str(), "");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, "a,b,");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv("");
        EXPECT_EQ(uris.size(), (size_t)1);
        EXPECT_EQ(uris[0].str(), "");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, "");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv(",");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "");
        EXPECT_EQ(uris[1].str(), "");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, ",");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv(",a");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "");
        EXPECT_EQ(uris[1].str(), "a");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, ",a");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv("a,");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "a");
        EXPECT_EQ(uris[1].str(), "");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, "a,");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv("\\,a");
        EXPECT_EQ(uris.size(), (size_t)1);
        EXPECT_EQ(uris[0].str(), ",a");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, "\\,a");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv("a,b\\\\c");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "a");
        EXPECT_EQ(uris[1].str(), "b\\c");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, "a,b\\\\c");
    }

    {
        std::vector<rawstd::URI> uris = rawstd::URI::uriv("\\\\,a");
        EXPECT_EQ(uris.size(), (size_t)2);
        EXPECT_EQ(uris[0].str(), "\\");
        EXPECT_EQ(uris[1].str(), "a");

        std::string s = rawstd::URI::uris(uris);
        EXPECT_EQ(s, "\\\\,a");
    }
}

} // namespace
