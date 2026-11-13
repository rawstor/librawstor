#ifndef RAWTLS_OP_HPP
#define RAWTLS_OP_HPP

#include <rawio/awaitable.hpp>

#include <rawstd/coro.hpp>

#include <coroutine>
#include <utility>
#include <variant>

namespace rawtls {

/*
 * What a Transport operation returns: either the rawio operation itself, when
 * the connection is plain and nothing stands between the caller and the
 * queue, or the Task that carries the same operation through TLS. Both are
 * started before the call returns, and co_await-ing either gives the same
 * result and throws the same std::system_error, so a caller cannot tell them
 * apart and a plain connection pays for no extra coroutine.
 */
template <typename T>
class Op final {
private:
    std::variant<rawio::Awaitable<T>, rawstd::Task<T>> _op;

public:
    Op(rawio::Awaitable<T>&& op) : _op(std::move(op)) {}
    Op(rawstd::Task<T>&& op) : _op(std::move(op)) {}
    Op(const Op&) = delete;
    Op& operator=(const Op&) = delete;
    Op(Op&&) noexcept = default;
    Op& operator=(Op&&) noexcept = default;

    bool await_ready() {
        return std::visit([](auto& op) { return op.await_ready(); }, _op);
    }

    void await_suspend(std::coroutine_handle<> h) {
        std::visit([h](auto& op) { op.await_suspend(h); }, _op);
    }

    T await_resume() {
        return std::visit([](auto& op) -> T { return op.await_resume(); }, _op);
    }
};

} // namespace rawtls

#endif // RAWTLS_OP_HPP
