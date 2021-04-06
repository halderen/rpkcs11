.DEFAULT: all
.PHONY: all clean analyze

MAINTAINERCLEANFILES=$(srcdir)/Makefile.in \
	config.log config.status \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub
CLEANFILES=$(srcdir)/*~ core* vgcore*
ACLOCAL_AMFLAGS = -Im4

AM_CFLAGS   = -DSYSCONFDIR=@sysconfdir@ -I/usr/include/tirpc
AM_CFLAGS  += -g -Wall -Wno-unused-variable

bin_PROGRAMS = pkcs11server pkcs11tool pkcs11test
lib_LTLIBRARIES = libpkcs11rpc.la libpkcs11null.la
noinst_LIBRARIES = libpkcs11common.a

EXTRA_DIST = $(srcdir)/COPYING $(srcdir)/LICENSE $(srcdir)/README.md
EXTRA_CLEAN  = core *~
EXTRA_CLEAN += pkcs11.h pkcs11_clnt.c pkcs11_svc.c pkcs11_xdr.c pkcs11_xdr.h

pkcs11server_SOURCES = pkcs11.h server.c rpcserver.c pkcs11_svc.c 
pkcs11server_LDADD   = libpkcs11common.a -lnsl -ltirpc -lpthread -ldl

pkcs11tool_SOURCES   = pkcs11.h pkcs11tool.c
pkcs11tool_LDADD     = -lnsl -ltirpc -lpthread -ldl

pkcs11test_SOURCES   = pkcs11.h pkcs11test.c
pkcs11test_LDADD     = -lnsl -ltirpc -lpthread -ldl

libpkcs11common_a_SOURCES = pkcs11_xdr.c
libpkcs11common_a_CFLAGS = $(AM_CFLAGS) -fPIC

libpkcs11rpc_la_SOURCES = pkcs11_clnt.c rpclibrary.c
libpkcs11rpc_la_LIBADD = libpkcs11common.a
libpkcs11null_la_SOURCES = pkcs11_clnt.c nulllibrary.c
libpkcs11null_la_LIBADD = libpkcs11common.a

clean-local:
	rm -f pkcs11.h pkcs11_clnt.c pkcs11_svc.c pkcs11_xdr.c pkcs11_xdr.h

server.c:	pkcs11.h
rpcserver.c:	pkcs11.h

pkcs11.h: pkcs11.x
	rpcgen -NMh $< > $@

pkcs11_xdr.c: pkcs11.x pkcs11.h
	rpcgen -NMc $< > $@

pkcs11_clnt.c: pkcs11.x pkcs11.h
	rpcgen -NMl $< > $@

pkcs11_svc.c: pkcs11.x pkcs11.h
	rpcgen -NMm $< > $@
