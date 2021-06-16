.DEFAULT: all
.PHONY: all clean analyze

MAINTAINERCLEANFILES=$(srcdir)/Makefile.in \
	config.log config.status \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub
CLEANFILES=$(srcdir)/*~ core* vgcore*
ACLOCAL_AMFLAGS= -Im4

AM_CFLAGS  = -DSYSCONFDIR=@sysconfdir@
AM_CFLAGS += -I/usr/include/tirpc
AM_CFLAGS += -O0 -g -Wall -Wno-unused-variable
#AM_CFLAGS += -O2 -g -Wall

#bin_PROGRAMS = pkcs11server
lib_LTLIBRARIES  = libchannelrpc.la libpkcs11null.la
# noinst_LIBRARIES = libpkcs11common.a
noinst_PROGRAMS = exampleprg examplesrv pkcs11tool pkcs11test
EXTRA_PROGRAMS = exampletst
EXTRA_DIST = $(srcdir)/COPYING $(srcdir)/LICENSE $(srcdir)/README.md
EXTRA_CLEAN  = core *~

otherincludedir = $(includedir)/channelrpc
otherinclude_HEADERS = channelrpc.h xdrdmem.h
libchannelrpc_la_SOURCES = channelrpc.c  channelrpc.h xdrdmem.c xdrdmem.h
libpkcs11null_la_SOURCES = pkcs11/nulllibrary.c

exampleprg_SOURCES  = example/exampleprg.c
exampleprg_SOURCES += example/mytransport.c c example/myclient.c
exampleprg_SOURCES += example/mytransport.h example/myapplication.h
exampleprg_CFLAGS   = $(AM_CFLAGS) -Iexample -I.. -DNOMODE
exampleprg_LDADD    = libchannelrpc.la -ltirpc -lnsl -lpthread -ldl
examplesrv_SOURCES  = example/examplesrv.c
examplesrv_SOURCES += example/myapplication.c example/mytransport.c example/sha256.c example/myserver.c
examplesrv_SOURCES += example/myapplication.h example/mytransport.h example/sha256.h
examplesrv_CFLAGS   = $(AM_CFLAGS) -Iexample -I.. -DNOMODE
examplesrv_LDADD    = libchannelrpc.la -ltirpc -lnsl -lpthread -ldl

exampletst_SOURCES  = example/exampleprg.c
exampletst_SOURCES += example/myapplication.c example/mytransport.c example/sha256.c example/myserver.c example/myclient.c
exampletst_SOURCES += example/myapplication.h example/mytransport.h example/sha256.h
exampletst_CFLAGS   = $(AM_CFLAGS) -Iexample -I..
exampletst_LDADD    = libchannelrpc.la -ltirpc -lnsl -lpthread -ldl

pkcs11tool_SOURCES   = pkcs11/pkcs11tool.c
pkcs11tool_LDADD     = -lnsl -lpthread -ldl

pkcs11test_SOURCES   = pkcs11/pkcs11test.c
pkcs11test_LDADD     = -lnsl -lpthread -ldl

# libpkcs11common_a_SOURCES = pkcs11_xdr.c
# libpkcs11common_a_CFLAGS = $(AM_CFLAGS) -fPIC

libpkcs11null_la_SOURCES = pkcs11/nulllibrary.c
# libpkcs11null_la_LIBADD  = libpkcs11common.a

#clean-local:
#	rm -f pkcs11.h pkcs11_clnt.c pkcs11_svc.c pkcs11_xdr.c pkcs11_xdr.h
