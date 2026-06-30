AC_INIT([librawstor], [m4_esyscmd_s(.github/tools/git-version.sh)])
AM_INIT_AUTOMAKE([1.9 tar-pax])

# AM_SILENT_RULES([yes])

AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_CXX

LT_INIT

AC_CONFIG_MACRO_DIRS([m4])


AC_SUBST([PACKAGE_VERSION_SHORT], [`echo ${PACKAGE_VERSION%%-*}`])
AC_SUBST([PACKAGE_VERSION_MAJOR], [`echo ${PACKAGE_VERSION_SHORT%%.*}`])
AC_SUBST([PACKAGE_VERSION_MINOR_PATCH], [`echo ${PACKAGE_VERSION_SHORT#*.}`])
AC_SUBST([PACKAGE_VERSION_MINOR], [`echo ${PACKAGE_VERSION_MINOR_PATCH%%.*}`])
AC_SUBST([PACKAGE_VERSION_PATCH], [`echo ${PACKAGE_VERSION_MINOR_PATCH#*.}`])
AC_SUBST([PACKAGE_VERSION_MAJOR_NEXT], [`expr $PACKAGE_VERSION_MAJOR + 1`])
AC_SUBST([PACKAGE_VERSION_MINOR_NEXT], [`expr $PACKAGE_VERSION_MINOR + 1`])
AC_SUBST([RPM_RELEASE], [`[[[ ${PACKAGE_VERSION} == *-* ]]] && RELEASE=${PACKAGE_VERSION#*-} && echo ${RELEASE//-/^} || echo "0"`])
AC_SUBST([LIBRARY_VERSION], [`VERSION=${PACKAGE_VERSION_SHORT%.*} && echo ${VERSION//./:}:0`])

AC_SUBST([GENERIC_CFLAGS], ["-std=gnu99 -Wall -Wextra -Werror"])
AC_SUBST([GENERIC_CXXFLAGS], ["-std=c++20 -Wall -Wextra -Werror"])


AC_ARG_ENABLE([tests], [AS_HELP_STRING([--disable-tests],
    [enable testing code])],
    [enable_tests=$enableval],
    [enable_tests="yes"])
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" == "xyes"])
AS_IF([test "x$enable_tests" == "xyes"], [
    PKG_CHECK_MODULES([GTEST], [gtest])
])


AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug],
    [enable DEBUG logging])],
    [enable_debug=$enableval],
    [enable_debug="no"])
AS_IF([test "x$enable_debug" == "xyes"], [
    AC_SUBST([maybe_loglevel_define], ["#define RAWSTD_LOGLEVEL RAWSTD_LOGLEVEL_DEBUG"])
])


AC_ARG_ENABLE([trace], [AS_HELP_STRING([--enable-trace],
    [enable TRACE logging])],
    [enable_trace=$enableval],
    [enable_trace="no"])
AS_IF([test "x$enable_trace" == "xyes"], [
    AC_SUBST([maybe_loglevel_define], ["#define RAWSTD_LOGLEVEL RAWSTD_LOGLEVEL_TRACE"])
])


AC_ARG_ENABLE([asan], [AS_HELP_STRING([--enable-asan],
    [Enable address sanitizer])],
    [enable_asan=$enableval],
    [enable_asan="no"])
AS_IF([test "x$enable_asan" == "xyes"], [
    AC_SUBST([ASAN_CFLAGS], ["-fsanitize=address -g"])
    AC_SUBST([ASAN_LDFLAGS], ["-fsanitize=address"])
    AC_SUBST([maybe_asan], ["-fsanitize=address"])
], [
    AC_SUBST([ASAN_CFLAGS], [""])
    AC_SUBST([ASAN_LDFLAGS], [""])
    AC_SUBST([maybe_asan], [""])
])


AC_ARG_WITH([liburing], [AS_HELP_STRING([--without-liburing],
    [disable support for liburing])],
    [with_liburing=$withval],
    [with_liburing="yes"])
AM_CONDITIONAL([WITH_LIBURING], [test "x$with_liburing" == "xyes"])
AS_IF([test "x$with_liburing" == "xyes"], [
    PKG_CHECK_MODULES([LIBURING], [liburing])
    AC_SUBST([maybe_liburing], ["liburing"])
    AC_DEFINE([RAWIO_WITH_LIBURING], 1, [Enable liburing integration])
], [
    AC_SUBST([maybe_liburing], [""])
])


AC_ARG_WITH([libxxhash], [AS_HELP_STRING([--without-libxxhash],
    [disable support for libxxhash])],
    [with_libxxhash=$withval],
    [with_libxxhash="yes"])
AM_CONDITIONAL([WITH_LIBXXHASH], [test "x$with_libxxhash" == "xyes"])
AS_IF([test "x$with_libxxhash" == "xyes"], [
    AC_DEFINE([RAWSTOR_WITH_LIBXXHASH], 1, [With libxxhash])
    PKG_CHECK_MODULES([LIBXXHASH], [libxxhash])
    AC_SUBST([maybe_libxxhash], ["libxxhash"])
], [
    AC_SUBST([maybe_libxxhash], [""])
])


AC_ARG_WITH([python3], [AS_HELP_STRING([--without-python3],
    [disable support for python3 bindings])],
    [with_python3=$withval],
    [with_python3="yes"])
AM_CONDITIONAL([WITH_PYTHON3], [test "x$with_python3" == "xyes"])
AS_IF([test "x$with_python3" == "xyes"], [
    AM_PATH_PYTHON([3.10], , [:])
    PKG_CHECK_MODULES([PYTHON3], [python3])
    AC_MSG_CHECKING([for python3-build usability])
    AS_IF([$PYTHON -m build --version >/dev/null 2>&1], [
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_ERROR([python3-build module not found])
    ])
])


AC_CONFIG_FILES(
    [Makefile]
    [include/rawstor/version.h]
    [librawstd/include/rawstd/logging_config.h]
    [librawstd/Makefile]
    [librawstd/src/Makefile]
    [librawstd/tests/Makefile]
    [librawio/Makefile]
    [librawio/src/Makefile]
    [librawio/tests/Makefile]
    [src/Makefile]
    [src/rawstor.pc]
    [cli/Makefile]
    [vhost/Makefile]
    [vhost/3rdparty/Makefile]
    [vhost/3rdparty/qemu/Makefile]
    [vhost/3rdparty/qemu/libvhost-user/Makefile]
    [ost/Makefile]
    [tests/Makefile]
    [deb/librawstor/control]
    [deb/python3-rawstor/control]
    [rpm/librawstor.spec]
    [pyrawstor/config.py]
    [pyrawstor/Makefile]
)

AC_OUTPUT
