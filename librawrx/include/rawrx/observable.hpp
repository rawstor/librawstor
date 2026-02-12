#ifndef RAWRX_OBSERVABLE_HPP
#define RAWRX_OBSERVABLE_HPP

#include <functional>
#include <tuple>
#include <utility>
#include <vector>

namespace rawrx {

template <typename... Args>
class Observable final {
private:
    std::function<void(const Args&...)> _subscription;

    std::vector<std::function<bool(Args&...)>> _modifiers;

    static void _noop(const Args&...) noexcept {}

public:
    Observable() noexcept : _subscription(_noop) {}

    Observable(const Observable&) = delete;

    Observable(Observable&& other) noexcept :
        _subscription(std::move(other._subscription)),
        _modifiers(std::move(other._modifiers)) {}

    Observable& operator=(const Observable&) = delete;

    Observable& operator=(Observable&& other) noexcept {
        _subscription = std::move(other._subscription);
        _modifiers = std::move(other._modifiers);
        return *this;
    }

    template <typename... U>
    void next(U&&... args) {
        std::tuple<Args...> values(std::forward<U>(args)...);

        for (auto& mod : _modifiers) {
            if (!std::apply(mod, values)) {
                return;
            }
        }

        std::apply(_subscription, values);
    }

    template <typename Callable>
    void subscribe(Callable&& callback) {
        _subscription = callback;
    }

    template <typename Modifier>
    Observable& pipe(Modifier&& modifier) {
        _modifiers.push_back(std::forward<Modifier>(modifier));
        return *this;
    }

    template <typename... Modifiers>
    Observable& pipe(Modifiers&&... modifiers) {
        (_modifiers.push_back(std::forward<Modifiers>(modifiers)), ...);
        return *this;
    }

    template <typename F>
    static auto map(F&& func) {
        return [func = std::forward<F>(func)](Args&... args) -> bool {
            func(args...);
            return true;
        };
    }

    template <typename F>
    static auto filter(F&& func) {
        return [func = std::forward<F>(func)](Args&... args) -> bool {
            return func(std::as_const(args)...);
        };
    }
};

} // namespace rawrx

#endif // RAWRX_OBSERVABLE_HPP
