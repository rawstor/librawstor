#include <gtest/gtest.h>

#include "backend.hpp"
#include "location.hpp"
#include "opts.h"
#include "rawio_sync.hpp"
#include "target.hpp"
#include "tenant.hpp"
#include "tmp_dir.hpp"

#include <rawstor/location.h>
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
    RawstdUUID id = rawstor::tenant_of(rawstd::URI("ost://10.0.0.1:7777"));
    EXPECT_TRUE(rawstd_uuid_is_nil(&id));
}

TEST(Tenant, address_with_tenant) {
    std::string text = std::string("ost://") + acme + "@10.0.0.1:7777";
    RawstdUUID id = rawstor::tenant_of(rawstd::URI(text));
    RawstdUUID expected = uuid(acme);
    EXPECT_EQ(rawstd_uuid_cmp(&id, &expected), 0);
}

TEST(Tenant, address_with_bad_tenant) {
    EXPECT_THROW(
        rawstor::tenant_of(rawstd::URI("ost://acme@10.0.0.1:7777")),
        std::system_error
    );
    EXPECT_THROW(
        rawstor::tenant_of(rawstd::URI("ost://*@10.0.0.1:7777")),
        std::system_error
    );
    EXPECT_THROW(
        rawstor::tenant_of(
            rawstd::URI(
                "ost://00000000-0000-0000-0000-000000000000@10.0.0.1:7777"
            )
        ),
        std::system_error
    );
}

TEST(Tenant, with_tenant) {
    rawstd::URI plain("ost://10.0.0.1:7777/path");
    rawstd::URI named = rawstor::with_tenant(plain, uuid(acme));
    EXPECT_EQ(
        named.str(), std::string("ost://") + acme + "@10.0.0.1:7777/path"
    );

    // No tenant is the address without user information.
    EXPECT_EQ(rawstor::with_tenant(named, RawstdUUID{}).str(), plain.str());
}

TEST(Tenant, with_tenant_keeps_a_host_less_address) {
    rawstd::URI plain("file:///var/lib/rawstor");
    rawstd::URI named = rawstor::with_tenant(plain, uuid(acme));
    EXPECT_EQ(named.str(), std::string("file://") + acme + "@/var/lib/rawstor");
    EXPECT_EQ(named.path().str(), "/var/lib/rawstor");
}

TEST(Tenant, tenant_follows_a_child_uri) {
    rawstd::URI named =
        rawstor::with_tenant(rawstd::URI("mds://10.0.0.2:7776"), uuid(acme));
    rawstd::URI child(named, "0197e0a2-7c3b-7d4e-8f10-000000000001");
    RawstdUUID id = rawstor::tenant_of(child);
    RawstdUUID expected = uuid(acme);
    EXPECT_EQ(rawstd_uuid_cmp(&id, &expected), 0);
}

// ---- over a real store (docs/tenants.md) ----

// A backend records the owner it is asked to create an object for, and the
// object's own metadata says so; none is recorded when none is given. Which
// owner a location stands for is decided above it (Location, Target).
TEST(TenantTest, an_object_records_the_owner_it_is_created_for) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    RawstdUUID owner = new_id();

    auto backend =
        run(*queue, rawstor::Backend::create(*queue, rawstd::URI(dir.uri())));
    RawstdUUID id = new_id();
    run(*queue,
        backend->create(
            RawstdUUID{}, id, 0, small_spec(), RAWSTOR_MEMBER_DATA, owner
        ));
    auto metas = run(*queue, backend->meta(id, 0));
    ASSERT_EQ(metas.size(), 1u);
    EXPECT_EQ(
        memcmp(metas[0].tenant_id, owner.bytes, sizeof(metas[0].tenant_id)), 0
    );

    RawstdUUID other_id = new_id();
    run(*queue, backend->create(
                    RawstdUUID{}, other_id, 0, small_spec(),
                    RAWSTOR_MEMBER_DATA, RawstdUUID{}
                ));
    auto other_metas = run(*queue, backend->meta(other_id, 0));
    ASSERT_EQ(other_metas.size(), 1u);
    RawstdUUID none{};
    EXPECT_EQ(
        memcmp(
            other_metas[0].tenant_id, none.bytes,
            sizeof(other_metas[0].tenant_id)
        ),
        0
    );
    run(*queue, backend->close());
}

// The tenant a location names owns what is created through it, and none
// names the default tenant: the owner is decided from the address of the
// object, not by the backend.
TEST(TenantTest, a_target_is_created_for_the_tenant_it_names) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    RawstdUUID owner = new_id();
    rawstd::URI plain(dir.uri());

    rawstor::Target named =
        run(*queue, rawstor::Location({rawstor::with_tenant(plain, owner)})
                        .create(*queue, small_spec()));
    rawstor::Target unnamed =
        run(*queue, rawstor::Location({plain}).create(*queue, small_spec()));

    auto tenant_of_copy = [&](const rawstor::Target& target) {
        auto metas = run(*queue, target.meta(*queue));
        EXPECT_EQ(metas.size(), 1u);
        return rawstor::tenant_from_wire(metas.front().tenant_id);
    };
    RawstdUUID got = tenant_of_copy(named);
    EXPECT_EQ(rawstd_uuid_cmp(&got, &owner), 0);
    RawstdUUID fallback = rawstor::default_tenant();
    got = tenant_of_copy(unnamed);
    EXPECT_EQ(rawstd_uuid_cmp(&got, &fallback), 0);

    // A tenant named for the object by a caller overrides the address.
    RawstdUUID other = new_id();
    rawstd::URI address(plain, "0197e0a2-7c3b-7d4e-8f10-000000000002");
    rawstor::Target explicit_owner(std::vector<rawstd::URI>{address});
    run(*queue, explicit_owner.create(*queue, small_spec(), other));
    got = tenant_of_copy(explicit_owner);
    EXPECT_EQ(rawstd_uuid_cmp(&got, &other), 0);
}

// A listing shows the objects a tenant owns; a location without a tenant, the
// administrator's, shows every object.
TEST(TenantTest, listing_shows_the_objects_a_tenant_owns) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    rawstd::URI in_acme = rawstor::with_tenant(plain, new_id());
    rawstd::URI in_other = rawstor::with_tenant(plain, new_id());

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
    EXPECT_EQ(listed(*queue, rawstor::with_tenant(plain, new_id())), 0u);
}

// A listing's targets name the owner of each object, also for the
// administrator, and none for the default tenant.
TEST(TenantTest, listed_targets_name_their_owner) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    RawstdUUID acme = new_id();
    RawstdUUID in_acme = new_id();
    RawstdUUID in_none = new_id();

    run(*queue, rawstor::Location({rawstor::with_tenant(plain, acme)})
                    .create(*queue, in_acme, small_spec()));
    run(*queue,
        rawstor::Location({plain}).create(*queue, in_none, small_spec()));

    std::list<rawstor::Target> targets;
    RawstorPaginationToken token = {};
    run(*queue, rawstor::Location({rawstor::with_tenant(plain, acme)})
                    .list(*queue, 0, targets, token));
    ASSERT_EQ(targets.size(), 1u);
    for (const rawstd::URI& uri : targets.front().uris()) {
        RawstdUUID named = rawstor::tenant_of(uri);
        EXPECT_EQ(rawstd_uuid_cmp(&named, &acme), 0);
    }

    // The administrator's listing: acme's object names acme, the other one
    // the default tenant by naming none.
    targets.clear();
    token = {};
    run(*queue, rawstor::Location({plain}).list(*queue, 0, targets, token));
    ASSERT_EQ(targets.size(), 2u);
    size_t named_acme = 0;
    for (const rawstor::Target& target : targets) {
        for (const rawstd::URI& uri : target.uris()) {
            RawstdUUID named = rawstor::tenant_of(uri);
            if (rawstd_uuid_is_nil(&named)) {
                RawstdUUID owner = rawstor::owner_of(uri);
                RawstdUUID fallback = rawstor::default_tenant();
                EXPECT_EQ(rawstd_uuid_cmp(&owner, &fallback), 0);
            } else {
                EXPECT_EQ(rawstd_uuid_cmp(&named, &acme), 0);
                ++named_acme;
            }
        }
    }
    EXPECT_EQ(named_acme, 1u);
}

// The filter comes before the page: a page of a tenant's objects is full even
// when objects of other tenants sort between them.
TEST(TenantTest, a_page_is_filled_with_the_objects_of_the_tenant) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    rawstd::URI acme = rawstor::with_tenant(plain, new_id());
    rawstd::URI other = rawstor::with_tenant(plain, new_id());

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

// The tenant a location names owns what is created through it and limits what
// is listed through it, and the targets name their owners.
TEST(TenantTest, a_location_names_the_tenant_through_the_c_api) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    RawstdUUID acme = new_id();
    RawstdUUID other = new_id();
    RawstdUUIDString acme_text;
    rawstd_uuid_to_string(&acme, &acme_text);

    // An administrator creates an object for acme by naming it.
    char target[512];
    RawstorObjectSpec spec = small_spec();
    rawstd::URI as_acme = rawstor::with_tenant(plain, acme);
    ssize_t res =
        rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_location_create(
                queue.get(), as_acme.str().c_str(), nullptr, &spec, target,
                sizeof(target), cb, data
            );
        });
    ASSERT_GT(res, 0);
    EXPECT_NE(std::string(target).find(acme_text), std::string::npos);
    char owner[64];
    ASSERT_GT(rawstor_target_tenant(target, owner, sizeof(owner)), 0);
    EXPECT_STREQ(owner, acme_text);

    auto list_as = [&](const rawstd::URI& location) {
        RawstorStringList* targets = nullptr;
        RawstorPaginationToken token = {};
        ssize_t lres =
            rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
                return rawstor_location_list(
                    queue.get(), location.str().c_str(), 0, &targets, &token,
                    cb, data
                );
            });
        EXPECT_EQ(lres, 0);
        size_t count = rawstor_string_list_size(targets);
        if (count == 1) {
            char listed[64];
            EXPECT_GT(
                rawstor_target_tenant(
                    *rawstor_string_list_iter(targets), listed, sizeof(listed)
                ),
                0
            );
            EXPECT_STREQ(listed, acme_text);
        }
        rawstor_string_list_delete(targets);
        return count;
    };
    EXPECT_EQ(list_as(as_acme), 1u);
    EXPECT_EQ(list_as(rawstor::with_tenant(plain, other)), 0u);
    EXPECT_EQ(list_as(plain), 1u);
}

// The tenant of a target string: the one it names, the default tenant when it
// names none, and an error for a string that names two.
TEST(TenantTest, the_tenant_of_a_target) {
    std::string object = "0197e0a2-7c3b-7d4e-8f10-000000000001";
    char buf[64];

    std::string named =
        std::string("ost://") + acme + "@10.0.0.1:7777/" + object;
    ASSERT_GT(rawstor_target_tenant(named.c_str(), buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, acme);

    std::string plain = "ost://10.0.0.1:7777/" + object;
    ASSERT_GT(rawstor_target_tenant(plain.c_str(), buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, RAWSTOR_DEFAULT_TENANT);

    // Mirrors of one object name one tenant.
    std::string mirrors = named + ",ost://" + acme + "@10.0.0.2:7777/" + object;
    ASSERT_GT(rawstor_target_tenant(mirrors.c_str(), buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, acme);
    std::string split = named + "," + plain;
    EXPECT_EQ(rawstor_target_tenant(split.c_str(), buf, sizeof(buf)), -EINVAL);

    // The length alone, as snprintf() does.
    EXPECT_EQ(rawstor_target_tenant(named.c_str(), nullptr, 0), 36);
}

// An object id is unique on its own: another tenant cannot create it again.
TEST(TenantTest, an_object_id_is_unique_across_tenants) {
    rawstor::tests::TmpDir dir;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    rawstd::URI plain(dir.uri());
    RawstdUUID id = new_id();

    run(*queue, rawstor::Location({rawstor::with_tenant(plain, new_id())})
                    .create(*queue, id, small_spec()));
    EXPECT_THROW(
        run(*queue, rawstor::Location({rawstor::with_tenant(plain, new_id())})
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
