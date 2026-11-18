#ifndef RAWSTOR_CLI_IMAGE_H
#define RAWSTOR_CLI_IMAGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Writes an object, or a version of it (a target that names one), to the
 * file `path`: rawstor_target_export(). */
int rawstor_cli_export(const char* target, const char* path);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_IMAGE_H
