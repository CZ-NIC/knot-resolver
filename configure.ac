AC_PREREQ(2.60)

# Version/identifiers
m4_define([VERSION_MAJOR],[0])
m4_define([VERSION_MINOR],[0])
m4_define([VERSION_MICRO],[2])
AC_INIT(knot-resolver, m4_defn([VERSION_MAJOR]).m4_defn([VERSION_MINOR]).m4_defn([VERSION_MICRO]), knot-dns@lists.nic.cz, knot-resolver)
AM_INIT_AUTOMAKE([gnits subdir-objects dist-xz -Wall -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Set compiler compatibility flags
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CPP_WERROR

# Default compiler flags
CFLAGS="$CFLAGS -Wall -Werror=format-security"

# Checks for programs.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR]) # call AM_PROG_AR only if available

# Linker
LT_INIT

# Use pkg-config
PKG_PROG_PKG_CONFIG

# Check for dependencies
AC_CHECK_FUNCS([opendir mkdtemp gettimeofday time])
PKG_CHECK_MODULES([libknot], [libknot])
PKG_CHECK_MODULES([libuv], [libuv], [build_daemon=yes], [build_daemon=no])
PKG_CHECK_MODULES([cmocka], [cmocka], [build_tests=yes], [build_tests=no])

# Check for python (integration tests)
AC_ARG_ENABLE([integration-tests],
	      AS_HELP_STRING([--enable-integration-tests], [enable integration tests (require Python devel), default: no]),
	      [build_integration=yes], [build_integration=no])
if test "x${build_integration}" == "xyes"; then
	AX_PYTHON_DEVEL([>= '2.5'])
fi

# Set up conditionals
AM_CONDITIONAL([BUILD_TESTS], [test "$build_tests" == "yes"])
AM_CONDITIONAL([BUILD_INTEGRATION], [test "$build_integration" == "yes"])
AM_CONDITIONAL([BUILD_DAEMON], [test "$build_daemon" == "yes"])

# Check for code coverage
AC_ARG_ENABLE([code-coverage],
	      AS_HELP_STRING([--enable-code-coverage], [enable code coverage, default: no]),
	      [code_coverage=yes], [code_coverage=no])
if test "x${code_coverage}" == "xyes"; then
	CFLAGS="${CFLAGS} --coverage -O0 -g"
fi


# Search other libraries
AC_SEARCH_LIBS([mdb_env_open], [lmdb])

# Config files
AC_CONFIG_FILES([Makefile lib/Makefile tests/Makefile daemon/Makefile])

# Output
AC_OUTPUT
AC_MSG_RESULT([
  $PACKAGE $VERSION

    Target:       $host_os $host_cpu
    Compiler:     ${CC}
    CFlags:       ${CFLAGS} ${CPPFLAGS} ${libuv_CFLAGS} ${libknot_CFLAGS}
    LDFlags:      ${LDFLAGS} ${libuv_LIBS} ${libknot_LIBS}

    Features:
    ---------
    Build tests:  ${build_tests} (integration ${build_integration})
    Build daemon: ${build_daemon}   

  Continue with 'make' command
])
