#include "uri.h"

#include <rawstd/uri.hpp>

#include <vector>

int rawstor_cli_location_add_target(
    const char* location, const struct RawstdUUID* uuid, char* target,
    size_t size
) {
    try {
        RawstdUUIDString uuid_string;
        rawstd_uuid_to_string(uuid, &uuid_string);

        std::vector<rawstd::URI> uris = rawstd::URI::uriv(location);
        std::vector<rawstd::URI> ret;
        ret.reserve(uris.size());
        for (const auto& location_uri : uris) {
            ret.emplace_back(location_uri, uuid_string);
        }
        return snprintf(target, size, "%s", rawstd::URI::uris(ret).c_str());
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    } catch (const std::exception&) {
        return -EINVAL;
    } catch (...) {
        return -EINVAL;
    }
}
