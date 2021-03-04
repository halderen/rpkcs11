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
AM_CFLAGS = -DSYSCONFDIR=@sysconfdir@ 

# CPPFLAGS += -D_REENTRANT
# CFLAGS += -g -Wall -Wno-unused-variable -fPIC -DDEBUG

AM_CFLAGS    = -I/usr/include/tirpc
AM_CFLAGS   += -g -Wall -Wno-unused-variable

bin_PROGRAMS = pkcs11server pkcs11tool
lib_LTLIBRARIES = libpkcs11rpc.la libpkcs11null.la

libpkcs11rpc_la_SOURCES = 
libpkcs11null_la_SOURCES = 


EXTRA_DIST = $(srcdir)/COPYING $(srcdir)/LICENSE $(srcdir)/README.md

pkcs11server_SOURCES   = pkcs11.h server.c rpcserver.c pkcs11_svc.c pkcs11_xdr.c
pkcs11server_LDADD     = -lnsl -ltirpc -lpthread -ldl

pkcs11tool_SOURCES     = pkcs11.h pkcs11tool.c
pkcs11tool_LDADD       = -lnsl -ltirpc -lpthread -ldl

libpkcs11rpc_SOURCES   = pkcs11_clnt.c pkcs11_xdr.c rpclibrary.c
libpkcs11null_SOURCES  = pkcs11_clnt.c pkcs11_xdr.c nulllibrary.c


# all: pkcs11tool pkcs11server libpkcs11rpc.so libpkcs11null.so

server.c:	pkcs11.h
rpcserver.c:	pkcs11.h

clean:
	rm -f core pkcs11.h *.o *.so pkcs11server pkcs11tool *~
	rm -f pkcs11_clnt.c pkcs11_svc.c pkcs11_xdr.c pkcs11_xdr.h

pkcs11.h: pkcs11.x
	rpcgen -NMh $< > $@

pkcs11_xdr.c: pkcs11.x pkcs11.h
	rpcgen -NMc $< > $@

pkcs11_clnt.c: pkcs11.x pkcs11.h
	rpcgen -NMl $< > $@

pkcs11_svc.c: pkcs11.x pkcs11.h
	rpcgen -NMm $< > $@
