#include "local_member.hpp"

#include <map>
#include <mutex>
#include <string>
#include <tuple>

namespace rawstor {

std::shared_ptr<LocalMember> local_member(
    const rawstd::URI& location, const RawstdUUID& id, uint64_t offset
) {
    using Key = std::tuple<std::string, std::string, uint64_t>;
    static std::mutex registry_mu;
    static std::map<Key, std::weak_ptr<LocalMember>> registry;

    Key key{
        location.str(),
        std::string(reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes)),
        offset
    };

    std::lock_guard<std::mutex> guard(registry_mu);
    for (auto it = registry.begin(); it != registry.end();) {
        it = it->second.expired() ? registry.erase(it) : std::next(it);
    }
    std::weak_ptr<LocalMember> slot = registry[key];
    std::shared_ptr<LocalMember> ret = slot.lock();
    if (!ret) {
        ret = std::make_shared<LocalMember>();
        registry[key] = ret;
    }
    return ret;
}

} // namespace rawstor
