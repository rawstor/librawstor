#include <gtest/gtest.h>

#include "backend.hpp"
#include "location.hpp"
#include "opts.h"
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

    // A location without a tenant creates objects that have none.
    auto plain =
        run(*queue, rawstor::Backend::create(*queue, rawstd::URI(dir.uri())));
    RawstdUUID other_id = new_id();
    run(*queue, plain->create(
                    RawstdUUID{}, other_id, 0, small_spec(), RAWSTOR_MEMBER_DATA
                ));
    auto plain_metas = run(*queue, plain->meta(other_id, 0));
    ASSERT_EQ(plain_metas.size(), 1u);
    RawstdUUID none{};
    EXPECT_EQ(
        memcmp(
            plain_metas[0].tenant_id, none.bytes,
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
