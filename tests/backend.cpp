#include "backend.hpp"
#include "server.hpp"

#include <filesystem>
#include <sstream>
#include <string>

namespace {

class BackendFile final : public rawstor::tests::Backend {
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

class BackendOST final : public rawstor::tests::Backend {
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

} // unnamed namespace

namespace rawstor {
namespace tests {

const std::vector<std::shared_ptr<Backend>> backends = {
    std::make_shared<BackendFile>(), std::make_shared<BackendOST>()
};

} // namespace tests
} // namespace rawstor
