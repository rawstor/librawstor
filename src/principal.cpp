#include <rawstor/principal.h>

#include "wire_backend.hpp"
#include <rawstd/gpp.hpp>
#include <rawtls/spiffe.hpp>

#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <system_error>

namespace {
rawstd::DetachedTask
run(rawio::Queue* queue, rawstd::URI location, RawstorFramePrincipal request,
    RawstorPrincipal** entries, size_t* count, int (*cb)(ssize_t, void*),
    void* data) {
    ssize_t result = 0;
    std::shared_ptr<rawstor::Backend> backend;
    try {
        backend = co_await rawstor::Backend::create(*queue, location);
        auto wire = std::dynamic_pointer_cast<rawstor::wire::Backend>(backend);
        if (!wire)
            RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
        auto response = co_await wire->exchange(
            &request, sizeof(request), request.head.cmd, 16 * 1024 * 1024
        );
        if (entries) {
            if (response.size() % sizeof(RawstorFramePrincipalPayload))
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            size_t size =
                response.size() / sizeof(RawstorFramePrincipalPayload);
            auto records = std::unique_ptr<RawstorPrincipal, decltype(&free)>(
                static_cast<RawstorPrincipal*>(
                    calloc(size ? size : 1, sizeof(RawstorPrincipal))
                ),
                free
            );
            if (!records)
                throw std::bad_alloc();
            for (size_t i = 0; i < size; ++i) {
                RawstorFramePrincipalPayload row;
                memcpy(&row, response.data() + i * sizeof(row), sizeof(row));
                if (!memchr(row.identity, 0, sizeof(row.identity)))
                    RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
                auto& entry = records.get()[i];
                memcpy(entry.identity, row.identity, sizeof(row.identity));
                entry.role = row.role;
                entry.rights = row.rights;
                RawstdUUID object{};
                memcpy(object.bytes, row.object_id, 16);
                if (!rawstd_uuid_is_nil(&object)) {
                    RawstdUUIDString text;
                    rawstd_uuid_to_string(&object, &text);
                    memcpy(entry.object_id, text, sizeof(text));
                }
            }
            *entries = records.release();
            *count = size;
        }
    } catch (const std::system_error& e) {
        result = -e.code().value();
    } catch (const std::bad_alloc&) {
        result = -ENOMEM;
    } catch (const std::exception&) {
        result = -EINVAL;
    }
    if (backend) {
        try {
            co_await backend->close();
        } catch (const std::system_error& e) {
            if (!result)
                result = -e.code().value();
        }
    }
    if (result < 0 && entries) {
        free(*entries);
        *entries = nullptr;
        *count = 0;
    }
    int res = cb(result, data);
    if (res < 0)
        RAWSTD_THROW_SYSTEM_ERROR(-res);
}
int start(
    RawIOQueue* queue, const char* location, RawstorCommandType command,
    const char* identity, unsigned int role, const char* object,
    unsigned int rights, RawstorPrincipal** entries, size_t* count,
    int (*cb)(ssize_t, void*), void* data
) noexcept {
    try {
        if (!queue || !location || !cb)
            return -EINVAL;
        if (entries) {
            *entries = nullptr;
            *count = 0;
        }
        rawstd::URI uri(location);
        if (uri.scheme() != "mds")
            return -ENOTSUP;
        RawstorFramePrincipal request{};
        request.head = {RAWSTOR_MAGIC, command, 0};
        if (identity) {
            rawtls::SpiffeId parsed(identity);
            if (parsed.role() != rawtls::Role::client)
                return -EINVAL;
            memcpy(request.payload.identity, identity, strlen(identity) + 1);
        }
        if (object) {
            RawstdUUID id{};
            if (rawstd_uuid_from_string(&id, object) < 0 ||
                rawstd_uuid_is_nil(&id))
                return -EINVAL;
            memcpy(request.payload.object_id, id.bytes, 16);
        }
        request.payload.role = role;
        request.payload.rights = rights;
        run(static_cast<rawio::Queue*>(queue), std::move(uri), request, entries,
            count, cb, data);
        rawstd::DetachedTask::rethrow_if_pending();
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    } catch (const std::exception&) {
        return -EINVAL;
    }
}
} // namespace
extern "C" {
int rawstor_principal_set(
    RawIOQueue* q, const char* loc, const char* id, unsigned int role,
    const char* object, unsigned int rights, int (*cb)(ssize_t, void*),
    void* data
) noexcept {
    if (!id)
        return -EINVAL;
    return start(
        q, loc, RAWSTOR_CMD_PRINCIPAL_SET, id, role, object, rights, nullptr,
        nullptr, cb, data
    );
}
int rawstor_principal_remove(
    RawIOQueue* q, const char* loc, const char* id, const char* object,
    int (*cb)(ssize_t, void*), void* data
) noexcept {
    if (!id)
        return -EINVAL;
    return start(
        q, loc, RAWSTOR_CMD_PRINCIPAL_REMOVE, id, 0, object, 0, nullptr,
        nullptr, cb, data
    );
}
int rawstor_principal_list(
    RawIOQueue* q, const char* loc, RawstorPrincipal** entries, size_t* count,
    int (*cb)(ssize_t, void*), void* data
) noexcept {
    if (!entries || !count)
        return -EINVAL;
    return start(
        q, loc, RAWSTOR_CMD_PRINCIPAL_LIST, nullptr, 0, nullptr, 0, entries,
        count, cb, data
    );
}
void rawstor_principal_list_delete(RawstorPrincipal* entries) noexcept {
    free(entries);
}
}
