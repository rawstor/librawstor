AC_INIT([librawstor], [0.0.0])
AM_INIT_AUTOMAKE

# AM_SILENT_RULES([yes])

AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

LT_INIT

AC_CONFIG_MACRO_DIRS([m4])


AC_ARG_ENABLE([tests], [AS_HELP_STRING([--disable-tests],
    [enable testing code])],
    [enable_tests=$enableval],
    [enable_tests="yes"])
AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" == "xyes"])


AC_ARG_ENABLE([ost], [AS_HELP_STRING([--disable-ost],
    [disable OST integration])],
    [enable_ost=$enableval],
    [enable_ost="yes"])
AM_CONDITIONAL([ENABLE_OST], [test "x$enable_ost" == "xyes"])
AS_IF([test "x$enable_ost" == "xyes"], [
    PKG_CHECK_MODULES([LIBXXHASH], [libxxhash])
    AC_SUBST([maybe_libxxhash], ["libxxhash"])
], [
    AC_SUBST([maybe_libxxhash], [""])
])

AC_ARG_WITH([liburing], [AS_HELP_STRING([--without-liburing],
    [disable support for liburing])],
    [with_liburing=$withval],
    [with_liburing="yes"])
AM_CONDITIONAL([WITH_LIBURING], [test "x$with_liburing" == "xyes"])
AS_IF([test "x$with_liburing" == "xyes"], [
    PKG_CHECK_MODULES([LIBURING], [liburing])
    AC_SUBST([maybe_liburing], ["liburing"])
], [
    AC_SUBST([maybe_liburing], [""])
])


AC_CONFIG_FILES(
    [Makefile]
    [src/Makefile]
    [src/rawstor.pc]
    [cli/Makefile]
    [vu/Makefile]
    [tests/Makefile]
)

AC_OUTPUT
