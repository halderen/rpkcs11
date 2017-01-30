.DEFAULT: all
.PHONY: all clean

CPPFLAGS += -D_REENTRANT
CFLAGS += -g -Wall -Wno-unused-variable -fPIC -DDEBUG
LDLIBS += -lnsl -lpthread -ldl

all: pkcs11tool pkcs11server libpkcs11rpc.so libpkcs11null.so

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

pkcs11server:		pkcs11_svc.o pkcs11_xdr.o rpcserver.o server.o
	$(LINK.c) -o $@ $^ $(LDLIBS)

pkcs11tool: pkcs11tool.c pkcs11.h
	$(LINK.c) -o $@ $^ $(LDLIBS)

libpkcs11rpc.so:	pkcs11_clnt.o pkcs11_xdr.o rpclibrary.o
	$(LINK.c) -o $@ $^ -shared

libpkcs11null.so:	pkcs11_clnt.o pkcs11_xdr.o nulllibrary.o
	$(LINK.c) -o $@ $^ -shared
