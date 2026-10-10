# Mirrors of the C API's own values, kept here rather than exported by
# the librawstor extension: module-level ints added from C grow its
# never-freed module dict, which LeakSanitizer reports at exit.

# ObjectSpec.failure_domain: RAWSTOR_OBJ_DOMAIN_* (<rawstor/protocol.h>).
OBJ_DOMAIN_DEFAULT = 0
OBJ_DOMAIN_OST = 1
OBJ_DOMAIN_SERVER = 2
OBJ_DOMAIN_RACK = 3
OBJ_DOMAIN_ROW = 4
OBJ_DOMAIN_DC = 5

# ObjectMeta.state: RAWSTOR_OBJECT_SYNC_STATE_*
# (<rawstor/target.h>).
OBJECT_SYNC_STATE_UNREACHABLE = 0
OBJECT_SYNC_STATE_CLEAN = 1
OBJECT_SYNC_STATE_DIRTY = 2
OBJECT_SYNC_STATE_LOST = 3

# ObjectMeta.role and ObjectConfig.roles: RAWSTOR_OBJECT_MEMBER_*
# (<rawstor/target.h>).
OBJECT_MEMBER_UNKNOWN = 0
OBJECT_MEMBER_IN_SYNC = 1
OBJECT_MEMBER_SYNCING = 2
OBJECT_MEMBER_EXCLUDED = 3

# Target.set_member_config() flags: RAWSTOR_CONFIG_* (<rawstor/target.h>).
CONFIG_CLEAR_LOST = 1

# ObjectMeta.member_role: RAWSTOR_MEMBER_* (<rawstor/target.h>).
MEMBER_DATA = 0
MEMBER_WITNESS = 1

# The names the CLI's own --failure-domain takes.
FAILURE_DOMAINS = {
    "ost": OBJ_DOMAIN_OST,
    "server": OBJ_DOMAIN_SERVER,
    "rack": OBJ_DOMAIN_RACK,
    "row": OBJ_DOMAIN_ROW,
    "dc": OBJ_DOMAIN_DC,
}
