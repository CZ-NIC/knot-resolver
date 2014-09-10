dnl A macro to check presence of liblmdb on the system
AC_DEFUN([AM_CHECK_LMDB],
[
    PKG_CHECK_EXISTS(lmdb,
        [AC_CHECK_HEADERS([lmdb.h],
            [], dnl We are only intrested in action-if-not-found
            [AC_MSG_WARN([Header file lmdb.h is required.])
             lmdb_required_headers="no"
            ]
        )
        AS_IF([test x"$lmdb_required_headers" != x"no"],
              [PKG_CHECK_MODULES([lmdb], [lmdb], [have_lmdb="yes"])]
        )],
        dnl PKG_CHECK_EXISTS ACTION-IF-NOT-FOUND
        [AC_MSG_WARN([No lmdb library found.])]
    )
    AM_CONDITIONAL([HAVE_LMDB], [test x$have_lmdb = xyes])
])

