AC_PREREQ(2.60)

# Version/identifiers
m4_define([VERSION_MAJOR],[0])
m4_define([VERSION_MINOR],[0])
m4_define([VERSION_MICRO],[1])
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

# Initialize libtool
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
LT_INIT

# Use pkg-config
PKG_PROG_PKG_CONFIG

# Check for dependencies
AM_CHECK_CMOCKA
AM_CHECK_LIBUV

# Check headers
AC_CHECK_HEADERS([stdlib.h],,, [AC_INCLUDES_DEFAULT])

# Search libraries
AC_SEARCH_LIBS([mdb_env_open], [lmdb])

# Config files
AC_CONFIG_FILES([Makefile
		 lib/Makefile
		 daemon/Makefile
		 tests/Makefile
		 ])

# Output
AC_OUTPUT
AC_MSG_RESULT([
  $PACKAGE $VERSION

    Target:   $host_os $host_cpu
    Compiler: ${CC}
    CFlags:   ${CFLAGS} ${CPPFLAGS}
    LDFlags:  ${LDFLAGS}
    Libs:     ${LIBS}

  Continue with 'make' command
])
