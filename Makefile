.DEFAULT: all
.PHONY: all clean

CPPFLAGS += -D_REENTRANT
CFLAGS += -g -Wall -fPIC
LDLIBS += -lnsl -lpthread -ldl

all: rpkcs11server librpkcs11.so pkcs11tool

clean:
	rm -f core pkcs11.h *.o pkcs11server pkcs11tool
	rm -f pkcs11_clnt.c pkcs11_svc.c pkcs11_xdr.c

pkcs11.h: pkcs11.x
	rpcgen -NMh $< > $@

pkcs11_xdr.c: pkcs11.x pkcs11.h
	rpcgen -NMc $< > $@

pkcs11_clnt.c: pkcs11.x pkcs11.h
	rpcgen -NMl $< > $@

pkcs11_svc.c: pkcs11.x pkcs11.h
	rpcgen -NMm $< > $@

rpkcs11server: pkcs11_svc.o pkcs11_xdr.o server.o
	$(LINK.c) -o $@ $^ $(LDLIBS)

pkcs11tool: pkcs11tool.c
	$(LINK.c) -o $@ $^ $(LDLIBS)

librpkcs11.so:	pkcs11_clnt.o pkcs11_xdr.o library.o
	$(LINK.c) -o $@ $^ -shared
