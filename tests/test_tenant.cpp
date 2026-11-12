#include <gtest/gtest.h>

#include "backend.hpp"
#include "location.hpp"
#include "opts.h"
#include "rawio_sync.hpp"
#include "target.hpp"
#include "tenant.hpp"
#include "tmp_dir.hpp"

#include <rawstor/protocol.h>

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <cstring>
#include <list>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace {

RawstdUUID uuid(const char* text) {
    RawstdUUID id;
    EXPECT_EQ(rawstd_uuid_from_string(&id, text), 0);
    return id;
}

const char* const acme = "0197e0a2-7c3b-7d4e-8f10-3a5b6c7d8e9f";

template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

RawstorObjectSpec small_spec() {
    return RawstorObjectSpec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
}

RawstdUUID new_id() {
    RawstdUUID id;
    EXPECT_EQ(rawstd_uuid7_init(&id), 0);
    return id;
}

size_t listed(rawio::Queue& queue, const rawstd::URI& location) {
    rawstor::Location loc({location});
    std::list<rawstor::Target> targets;
    RawstorPaginationToken token = {};
    run(queue, loc.list(queue, 0, targets, token));
    return targets.size();
}

} // namespace

TEST(Tenant, an_address_without_a_tenant_names_none) {
    RawstdUUID id = rawstor::tenant::of(rawstd::URI("ost://10.0.0.1:7777"));
    EXPECT_TRUE(rawstd_uuid_is_nil(&id));
}

TEST(Tenant, address_with_tenant) {
    std::string text = std::string("ost://") + acme + "@10.0.0.1:7777";
    RawstdUUID id = rawstor::tenant::of(rawstd::URI(text));
    RawstdUUID expected = uuid(acme);
    EXPECT_EQ(rawstd_uuid_cmp(&id, &expected), 0);
}

TEST(Tenant, address_with_bad_tenant) {
    EXPECT_THROW(
        rawstor::tenant::of(rawstd::URI("ost://acme@10.0.0.1:7777")),
        std::system_error
    );
    EXPECT_THROW(
        rawstor::tenant::of(rawstd::URI("ost://*@10.0.0.1:7777")),
        std::system_error
    );
    EXPECT_THROW(
        rawstor::tenant::of(
            rawstd::URI(
                "ost://00000000-0000-0000-0000-000000000000@10.0.0.1:7777"
            )
        ),
        std::system_error
    );
}

TEST(Tenant, with_tenant) {
    rawstd::URI plain("ost://10.0.0.1:7777/path");
    rawstd::URI named = rawstor::tenant::with(plain, uuid(acme));
    EXPECT_EQ(
        named.str(), std::string("ost://") + acme + "@10.0.0.1:7777/path"
    );

    // No tenant is the address without user information.
    EXPECT_EQ(rawstor::tenant::with(named, RawstdUUID{}).str(), plain.str());
}

TEST(Tenant, with_tenant_keeps_a_host_less_address) {
    rawstd::URI plain("file:///var/lib/rawstor");
    rawstd::URI named = rawstor::tenant::with(plain, uuid(acme));
    EXPECT_EQ(named.str(), std::string("file://") + acme + "@/var/lib/rawstor");
    EXPECT_EQ(named.path().str(), "/var/lib/rawstor");
}

TEST(Tenant, tenant_follows_a_child_uri) {
    rawstd::URI named =
        rawstor::tenant::with(rawstd::URI("mds://10.0.0.2:7776"), uuid(acme));
    rawstd::URI child(named, "0197e0a2-7c3b-7d4e-8f10-000000000001");
    RawstdUUID id = rawstor::tenant::of(child);
    RawstdUUID expected = uuid(acme);
    EXPECT_EQ(rawstd_uuid_cmp(&id, &expected), 0);
}

// ---- over a real store (docs/tenants.md) ----

// The tenant a location names owns the objects created through it, and the
// object's own metadata says so.
TEST(TenantTest, an_object_records_the_tenant_that_created_it) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    RawstdUUID owner = new_id();
    rawstd::URI location = rawstor::tenant::with(rawstd::URI(dir.uri()), owner);

    RawstdUUID id = new_id();
    auto backend = run(*queue, rawstor::Backend::create(*queue, location));
    run(*queue, backend->create(
                    RawstdUUID{}, id, 0, small_spec(), RAWSTOR_MEMBER_DATA
                ));
    auto metas = run(*queue, backend->meta(id, 0));
    ASSERT_EQ(metas.size(), 1u);
    EXPECT_EQ(
        memcmp(metas[0].tenant_id, owner.bytes, sizeof(metas[0].tenant_id)), 0
    );
    run(*queue, backend->close());

    // A location without a tenant creates objects of the default tenant.
    auto plain =
        run(*queue, rawstor::Backend::create(*queue, rawstd::URI(dir.uri())));
    RawstdUUID other_id = new_id();
    run(*queue, plain->create(
                    RawstdUUID{}, other_id, 0, small_spec(), RAWSTOR_MEMBER_DATA
                ));
    auto plain_metas = run(*queue, plain->meta(other_id, 0));
    ASSERT_EQ(plain_metas.size(), 1u);
    RawstdUUID fallback = rawstor::tenant::default_tenant();
    EXPECT_EQ(
        memcmp(
            plain_metas[0].tenant_id, fallback.bytes,
            sizeof(plain_metas[0].tenant_id)
        ),
        0
    );
    run(*queue, plain->close());
}

// A listing shows the objects a tenant owns; a location without a tenant, the
// administrator's, shows every object.
TEST(TenantTest, listing_shows_the_objects_a_tenant_owns) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    rawstd::URI in_acme = rawstor::tenant::with(plain, new_id());
    rawstd::URI in_other = rawstor::tenant::with(plain, new_id());

    run(*queue,
        rawstor::Location({in_acme}).create(*queue, new_id(), small_spec()));
    run(*queue,
        rawstor::Location({in_acme}).create(*queue, new_id(), small_spec()));
    run(*queue,
        rawstor::Location({in_other}).create(*queue, new_id(), small_spec()));
    run(*queue,
        rawstor::Location({plain}).create(*queue, new_id(), small_spec()));

    EXPECT_EQ(listed(*queue, in_acme), 2u);
    EXPECT_EQ(listed(*queue, in_other), 1u);
    EXPECT_EQ(listed(*queue, plain), 4u);
    EXPECT_EQ(listed(*queue, rawstor::tenant::with(plain, new_id())), 0u);
}

// A listing tells who owns each object, also for the administrator, and a
// target names no tenant.
TEST(TenantTest, listing_tells_the_owner_of_each_object) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    RawstdUUID acme = new_id();
    RawstdUUID in_acme = new_id();
    RawstdUUID in_none = new_id();

    run(*queue, rawstor::Location({rawstor::tenant::with(plain, acme)})
                    .create(*queue, in_acme, small_spec()));
    run(*queue,
        rawstor::Location({plain}).create(*queue, in_none, small_spec()));

    std::list<rawstor::Target> targets;
    std::vector<RawstdUUID> owners;
    RawstorPaginationToken token = {};
    run(*queue, rawstor::Location({rawstor::tenant::with(plain, acme)})
                    .list(*queue, 0, targets, token, &owners));
    ASSERT_EQ(owners.size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&owners[0], &acme), 0);
    for (const rawstd::URI& uri : targets.front().uris()) {
        EXPECT_TRUE(uri.username().empty());
    }

    targets.clear();
    owners.clear();
    token = {};
    run(*queue,
        rawstor::Location({plain}).list(*queue, 0, targets, token, &owners));
    ASSERT_EQ(owners.size(), 2u);
    size_t owned = 0;
    for (const RawstdUUID& owner : owners) {
        if (rawstd_uuid_cmp(&owner, &acme) == 0) {
            ++owned;
        } else {
            RawstdUUID fallback = rawstor::tenant::default_tenant();
            EXPECT_EQ(rawstd_uuid_cmp(&owner, &fallback), 0);
        }
    }
    EXPECT_EQ(owned, 1u);
}

// The filter comes before the page: a page of a tenant's objects is full even
// when objects of other tenants sort between them.
TEST(TenantTest, a_page_is_filled_with_the_objects_of_the_tenant) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    rawstd::URI acme = rawstor::tenant::with(plain, new_id());
    rawstd::URI other = rawstor::tenant::with(plain, new_id());

    // Ids sort in creation order.
    for (int i = 0; i < 3; ++i) {
        run(*queue,
            rawstor::Location({other}).create(*queue, new_id(), small_spec()));
    }
    for (int i = 0; i < 3; ++i) {
        run(*queue,
            rawstor::Location({acme}).create(*queue, new_id(), small_spec()));
    }

    rawstor::Location location({acme});
    std::list<rawstor::Target> targets;
    RawstorPaginationToken token = {};
    run(*queue, location.list(*queue, 2, targets, token));
    EXPECT_EQ(targets.size(), 2u);
    EXPECT_FALSE(rawstor_pagination_token_empty(&token));
    run(*queue, location.list(*queue, 2, targets, token));
    EXPECT_EQ(targets.size(), 1u);
}

// An explicit tenant stands in for the one a location names, for the listing
// and for the object a create makes.
TEST(TenantTest, an_explicit_tenant_overrides_the_location) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    RawstdUUID acme = new_id();
    RawstdUUID other = new_id();
    RawstdUUIDString acme_text;
    rawstd_uuid_to_string(&acme, &acme_text);
    RawstdUUIDString other_text;
    rawstd_uuid_to_string(&other, &other_text);

    // An administrator, naming no tenant, creates an object for acme.
    char target[512];
    RawstorObjectSpec spec = small_spec();
    ssize_t res =
        rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_location_create(
                queue.get(), plain.str().c_str(), acme_text, nullptr, &spec,
                target, sizeof(target), cb, data
            );
        });
    ASSERT_GT(res, 0);
    EXPECT_EQ(std::string(target).find('@'), std::string::npos);

    auto list_for = [&](const char* tenant) {
        RawstorStringList* targets = nullptr;
        RawstorStringList* tenants = nullptr;
        RawstorPaginationToken token = {};
        ssize_t lres =
            rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
                return rawstor_location_list(
                    queue.get(), plain.str().c_str(), tenant, 0, &targets,
                    &tenants, &token, cb, data
                );
            });
        EXPECT_EQ(lres, 0);
        size_t count = rawstor_string_list_size(targets);
        if (count == 1) {
            EXPECT_STREQ(*rawstor_string_list_iter(tenants), acme_text);
        }
        rawstor_string_list_delete(targets);
        rawstor_string_list_delete(tenants);
        return count;
    };
    EXPECT_EQ(list_for(acme_text), 1u);
    EXPECT_EQ(list_for(other_text), 0u);
    EXPECT_EQ(list_for(nullptr), 1u);
}

// An object id is unique on its own: another tenant cannot create it again.
TEST(TenantTest, an_object_id_is_unique_across_tenants) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    RawstdUUID id = new_id();

    run(*queue, rawstor::Location({rawstor::tenant::with(plain, new_id())})
                    .create(*queue, id, small_spec()));
    EXPECT_THROW(
        run(*queue, rawstor::Location({rawstor::tenant::with(plain, new_id())})
                        .create(*queue, id, small_spec())),
        std::system_error
    );
}

// Only an MDS keeps a tenant registry.
TEST(TenantTest, a_store_without_a_registry_has_no_tenants) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::vector<RawstdUUID> tenants;
    try {
        run(
            *queue,
            rawstor::Location({rawstd::URI(dir.uri())}).tenants(*queue, tenants)
        );
        FAIL() << "listed tenants of a store without a registry";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ENOTSUP);
    }
}
