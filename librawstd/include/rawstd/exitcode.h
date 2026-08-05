#ifndef RAWSTD_EXITCODE_H
#define RAWSTD_EXITCODE_H

#ifdef __cplusplus
extern "C" {
#endif

// Maps a positive errno value to a sysexits.h EX_* exit code, so every
// rawstor binary reports the same exit code for the same underlying
// failure. Falls back to EX_OSERR for anything not specifically mapped.
int rawstd_exitcode_for_errno(int err);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_EXITCODE_H
