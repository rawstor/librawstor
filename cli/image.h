#ifndef RAWSTOR_CLI_IMAGE_H
#define RAWSTOR_CLI_IMAGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Shows progress on stderr: a line rewritten in place on a terminal, a line
 * per 10% otherwise. rawstor_cli_progress_end() finishes the display (before
 * anything else is printed) with `result`, that of the operation: 100% for
 * success, the last percentage reached for a failure. */
void rawstor_cli_progress(int percent);
void rawstor_cli_progress_end(int result);

/* Writes an object, or a version of it (a target that names one), to the
 * file `path`: rawstor_target_export(), `force` opening it below quorum. */
int rawstor_cli_export(const char* target, const char* path, int force);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_IMAGE_H
