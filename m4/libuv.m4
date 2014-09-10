dnl A macro to check presence of libuv on the system
AC_DEFUN([AM_CHECK_LIBUV],
[
    PKG_CHECK_EXISTS(libuv,
        [AC_CHECK_HEADERS([uv.h],
            [], dnl We are only intrested in action-if-not-found
            [AC_MSG_WARN([Header file uv.h is required.])
             libuv_required_headers="no"
            ]
        )
        AS_IF([test x"$libuv_required_headers" != x"no"],
              [PKG_CHECK_MODULES([libuv], [libuv], [have_libuv="yes"])]
        )],
        dnl PKG_CHECK_EXISTS ACTION-IF-NOT-FOUND
        [AC_MSG_WARN([No libuv library found, libuv tests will not be built])]
    )
    AM_CONDITIONAL([HAVE_LIBUV], [test x$have_libuv = xyes])
])

