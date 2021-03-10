AC_PREREQ([2.69])
AC_INIT([rpkcs11], [0.1-dev], [http://github.org/halderen/rpkcs11/])
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE
LT_INIT
dnl AC_CONFIG_SRCDIR([server.c])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AM_PROG_CC_C_O
dnl CHECK_COMPILER_FLAG(std=c99, [C99FLAG="-std=c99"])
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h])
AC_CHECK_FUNCS([strrchr])
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AX_C___ATTRIBUTE__

AX_PTHREAD
AC_CHECK_LIB(pthread, pthread_barrier_wait, [AC_DEFINE([HAVE_PTHREAD_BARRIER], [1], [Define if pthread barrier supported])])

AX_DEFINE_DIR([STATEDIR], localstatedir, [Location of logging])
AX_DEFINE_DIR([BINDIR], bindir, [Location of executables])

AC_ARG_WITH(pkcs11-module, 
  AS_HELP_STRING([--with-pkcs11-module=PATH],[specify path of a PKCS#11 library (default PREFIX/lib/softhsm/libsofthsm2.so)]),
	[ pkcs11_module="$withval" ],
	[ pkcs11_module="$full_libdir/softhsm/libsofthsm2.so" ]
)
AC_SUBST(PKCS11_MODULE, "$pkcs11_module")
AC_DEFINE_UNQUOTED(PKCS11_MODULE, "$pkcs11_module", [Shared library to use as PKCS#11 module])

AC_ARG_WITH(pkcs11-host, 
  AS_HELP_STRING([--with-pkcs11-host=PATH],[target hostname)]),
	[ pkcs11_host="$withval" ],
	[ pkcs11_host="" ]
)
AC_SUBST(PKCS11_HOST, "$pkcs11_host")
AC_DEFINE_UNQUOTED(PKCS11_HOST, "$pkcs11_host", [target hostname])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
