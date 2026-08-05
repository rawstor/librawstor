#include "rawstd/exitcode.h"

#include <errno.h>
#include <sysexits.h>

int rawstd_exitcode_for_errno(int err) {
    switch (err) {
    case ENOENT:
        return EX_NOINPUT;

    case ECONNREFUSED:
    case ETIMEDOUT:
    case EHOSTUNREACH:
    case ENETUNREACH:
        return EX_UNAVAILABLE;

    case EACCES:
    case EPERM:
        return EX_NOPERM;

    default:
        return EX_OSERR;
    }
}
