#ifndef RAWSTOR_CLI_SNAPSHOT_H
#define RAWSTOR_CLI_SNAPSHOT_H

#ifdef __cplusplus
extern "C" {
#endif

/* `uuid`: NULL to let the library pick the version id (target's own bound
 * one, or a freshly generated one -- see rawstor_target_create_snapshot()),
 * or a caller-chosen UUID string (only valid when `target` is plain). */
int rawstor_cli_snapshot(const char* target, const char* uuid);

/* Prints every snapshot of `target`'s object, one target string per
 * line, oldest first (rawstor_target_snapshots()). */
int rawstor_cli_list_snapshots(const char* target);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_SNAPSHOT_H
