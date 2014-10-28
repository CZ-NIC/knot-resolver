dnl A macro to check presence of libuv on the system
AC_DEFUN([AM_CHECK_LIBUV],
[
	AC_CHECK_HEADERS([uv.h], [], [AC_MSG_ERROR([Header file uv.h is required.])])
	AC_CHECK_LIB([uv], [uv_version], [], [AC_MSG_ERROR([libuv is required.])])
])

