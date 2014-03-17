# libcouchbase

AC_DEFUN([AX_LIBCOUCHBASE], [
    AC_CHECK_HEADER([libcouchbase/couchbase.h], [
      AC_CACHE_CHECK([check for -lcouchbase], [ax_cv_libcouchbase], [
        AC_LANG_PUSH([C])
        AX_SAVE_FLAGS
        LIBS="-lcouchbase $LIBS"
        AC_RUN_IFELSE([
          AC_LANG_PROGRAM([#include <libcouchbase/couchbase.h>], [
                lcb_error_t err;
                lcb_t instance;
                struct lcb_create_st create_options;
            ])],
          [ax_cv_libcouchbase=yes],
          [ax_cv_libcouchbase=no],
          [AC_MSG_WARN([test program execution failed])])
        AC_LANG_POP
        AX_RESTORE_FLAGS
        ])
      ])

  AS_IF([test "x$ax_cv_libcouchbase" = "xyes"], [
      AC_DEFINE([HAVE_LIBCOUCHBASE_COUCHBASE_H], [1], [Have libcouchbase/couchbase.h])
      ],[
      AC_DEFINE([HAVE_LIBCOUCHBASE_COUCHBASE_H], [0], [Have libcouchbase/couchbase.h])
      ])
  ])

AC_DEFUN([_ENABLE_LIBCOUCHBASE], [
         AC_REQUIRE([AX_LIBCOUCHBASE])

         AC_ARG_ENABLE([libcouchbase],
                       [AS_HELP_STRING([--disable-libcouchbase],
                                       [Build with libcouchbase support @<:@default=on@:>@])],
                       [ax_enable_libcouchbase="$enableval"],
                       [ax_enable_libcouchbase="yes"])

         AS_IF([test "x$ax_cv_libcouchbase" != "xyes"], [
               ax_enable_libcouchbase="not found"
               ])

         AS_IF([test "x$ax_enable_libcouchbase" = "xyes"], [
               AC_DEFINE([HAVE_LIBCOUCHBASE], [1], [Enable libcouchbase support])
               LIBCOUCHBASE_CFLAGS=
               AC_SUBST([LIBCOUCHBASE_CFLAGS])
               LIBCOUCHBASE_LDFLAGS="-lcouchbase"
               AC_SUBST([LIBCOUCHBASE_LDFLAGS])
            ],[])

         AM_CONDITIONAL(HAVE_LIBCOUCHBASE, test "x${ax_enable_libcouchbase}" = "xyes")
         ])

AC_DEFUN([AX_ENABLE_LIBCOUCHBASE], [ AC_REQUIRE([_ENABLE_LIBCOUCHBASE]) ])
