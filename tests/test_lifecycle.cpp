#include "fixture.hpp"

#include "server.hpp"

#include <rawstor/object.h>

#include <rawstorstd/gpp.hpp>

#include <gtest/gtest.h>

#include <cstring>

namespace {

class Backend {
public:
    virtual ~Backend() = default;

    virtual void accept() = 0;

    virtual void wait() = 0;

    virtual void close() = 0;

    virtual std::string uris() const noexcept = 0;

    virtual std::string protocol() const noexcept = 0;
};

class BackendFile final : public Backend {
private:
    std::filesystem::path _path;
    std::string _uris;

public:
    BackendFile() :
        _path(std::filesystem::temp_directory_path() / "test_objects") {
        std::filesystem::create_directory(_path);
        std::ostringstream oss;
        oss << "file://" << _path.string();
        _uris = oss.str();
    }
    ~BackendFile() { std::filesystem::remove_all(_path); }

    void accept() override {}

    void wait() override {}

    void close() override {}

    std::string uris() const noexcept override { return _uris; }

    std::string protocol() const noexcept override { return "file"; }
};

class BackendOST final : public Backend {
private:
    rawstor::tests::Server _server;

public:
    BackendOST() : _server(8753) {}

    void accept() override { _server.accept(); }

    void wait() override { _server.wait(); }

    void close() override { _server.close(); }

    std::string uris() const noexcept override {
        return "ost://127.0.0.1:8753";
    }

    std::string protocol() const noexcept override { return "ost"; }
};

const std::vector<std::shared_ptr<Backend>> backends = {
    std::make_shared<BackendFile>(), std::make_shared<BackendOST>()
};

class LifecycleTest : public testing::TestWithParam<std::shared_ptr<Backend>> {
protected:
    std::shared_ptr<Backend> _backend;

    void SetUp() override { _backend = GetParam(); }

    LifecycleTest() {}

    ~LifecycleTest() {}
};

TEST_P(LifecycleTest, create_spec_remove) {
    _backend->accept();
    RawstorObjectSpec spec{.size = 1ull << 20};
    char object_uris[1024] = {};
    int res = rawstor_object_create(
        _backend->uris().c_str(), &spec, object_uris, sizeof(object_uris)
    );
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, (int)strlen(object_uris));
    _backend->close();

    _backend->accept();
    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(object_uris, &read_spec);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, 0);
    if (_backend->protocol() == "ost") {
        // rawstor_object_spec emulated
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 30));
    } else {
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }
    _backend->close();

    // rawstor_object_remove not implemented for OST
    if (_backend->protocol() != "ost") {
        _backend->accept();
        res = rawstor_object_remove(object_uris);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
        EXPECT_EQ(res, 0);
        _backend->close();
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllBackends, LifecycleTest, ::testing::ValuesIn(backends),
    [](const ::testing::TestParamInfo<std::shared_ptr<Backend>>& info) {
        return info.param->protocol();
    }
);

} // unnamed namespace
