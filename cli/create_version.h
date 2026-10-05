#ifndef RAWSTOR_CLI_CREATE_VERSION_H
#define RAWSTOR_CLI_CREATE_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

/* `uuid`: NULL to let the library pick the version id (target's own bound
 * one, or a freshly generated one -- see rawstor_target_create_version()),
 * or a caller-chosen UUID string (only valid when `target` is plain). */
int rawstor_cli_create_version(const char* target, const char* uuid);

/* Prints every version of `target`'s object, one target string per
 * line, oldest first (rawstor_target_versions()). */
int rawstor_cli_list_versions(const char* target);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_CREATE_VERSION_H
