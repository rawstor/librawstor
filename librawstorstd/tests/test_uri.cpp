#include "rawstorstd/uri.hpp"

#include "unittest.h"


namespace {


int test_uri_empty() {
    rawstor::URI uri("");

    assertTrue(uri.str() == "");
    assertTrue(uri.scheme() == "");
    assertTrue(uri.userinfo() == "");
    assertTrue(uri.username() == "");
    assertTrue(uri.password() == "");
    assertTrue(uri.authority() == "");
    assertTrue(uri.host() == "");
    assertTrue(uri.hostname() == "");
    assertTrue(uri.port() == 0);
    assertTrue(uri.path().str() == "");
    assertTrue(uri.path().dirname() == "");
    assertTrue(uri.path().filename() == "");

    return 0;
}


int test_uri_http() {
    rawstor::URI uri("http://user:password@example.com:80/foo");

    assertTrue(uri.str() == "http://user:password@example.com:80/foo");
    assertTrue(uri.scheme() == "http");
    assertTrue(uri.userinfo() == "user:password");
    assertTrue(uri.username() == "user");
    assertTrue(uri.password() == "password");
    assertTrue(uri.authority() == "user:password@example.com:80");
    assertTrue(uri.host() == "example.com:80");
    assertTrue(uri.hostname() == "example.com");
    assertTrue(uri.port() == 80);
    assertTrue(uri.path().str() == "/foo");
    assertTrue(uri.path().dirname() == "");
    assertTrue(uri.path().filename() == "foo");

    return 0;
}


int test_uri_file() {
    rawstor::URI uri("file:///tmp/foo");

    assertTrue(uri.str() == "file:///tmp/foo");
    assertTrue(uri.scheme() == "file");
    assertTrue(uri.userinfo() == "");
    assertTrue(uri.username() == "");
    assertTrue(uri.password() == "");
    assertTrue(uri.authority() == "");
    assertTrue(uri.host() == "");
    assertTrue(uri.hostname() == "");
    assertTrue(uri.port() == 0);
    assertTrue(uri.path().str() == "/tmp/foo");
    assertTrue(uri.path().dirname() == "/tmp");
    assertTrue(uri.path().filename() == "foo");

    return 0;
}


int test_uri_empty_path() {
    rawstor::URI uri("ost://127.0.0.1:8080");

    assertTrue(uri.str() == "ost://127.0.0.1:8080");
    assertTrue(uri.scheme() == "ost");
    assertTrue(uri.userinfo() == "");
    assertTrue(uri.username() == "");
    assertTrue(uri.password() == "");
    assertTrue(uri.authority() == "127.0.0.1:8080");
    assertTrue(uri.host() == "127.0.0.1:8080");
    assertTrue(uri.hostname() == "127.0.0.1");
    assertTrue(uri.port() == 8080);
    assertTrue(uri.path().str() == "");

    return 0;
}


} // unnamed


int main() {
    int rval = 0;
    rval += test_uri_empty();
    rval += test_uri_http();
    rval += test_uri_file();
    rval += test_uri_empty_path();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
