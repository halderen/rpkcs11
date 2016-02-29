.DEFAULT: all
.PHONY: all clean

CPPFLAGS += -D_REENTRANT
CFLAGS += -g -Wall -Wno-unused-variable -fPIC
LDLIBS += -lnsl -lpthread -ldl

all: pkcs11tool pkcs11server libpkcs11rpc.so libpkcs11door.so

clean:
	rm -f core pkcs11.h doorrpc.h *.o *.so pkcs11server pkcs11tool *~
	rm -f pkcs11_clnt.c pkcs11_svc.c pkcs11_xdr.c
	rm -f door_clnt.c door_svc.c door_xdr.c

pkcs11.h: pkcs11.x
	rpcgen -NMh $< > $@

pkcs11_xdr.c: pkcs11.x pkcs11.h
	rpcgen -NMc $< > $@

pkcs11_clnt.c: pkcs11.x pkcs11.h
	rpcgen -NMl $< > $@

pkcs11_svc.c: pkcs11.x pkcs11.h
	rpcgen -NMm $< > $@

doorrpc.h: doorrpc.x
	rpcgen -NMh $< > $@

doorrpc_xdr.c: doorrpc.x doorrpc.h
	rpcgen -NMc $< > $@

doorrpc_clnt.c: doorrpc.x doorrpc.h
	rpcgen -NMl $< > $@

doorrpc_svc.c: doorrpc.x doorrpc.h
	rpcgen -NMm $< > $@

pkcs11server:		doorrpc_svc.o doorrpc_xdr.o doorserver.o door.o \
			pkcs11_svc.o pkcs11_xdr.o rpcserver.o server.o
	$(LINK.c) -o $@ $^ $(LDLIBS)

pkcs11tool: pkcs11tool.c doorrpc_clnt.o doorrpc_xdr.o doorlibrary.o door.o
	$(LINK.c) -o $@ $^ $(LDLIBS)

libpkcs11door.so:	doorrpc_clnt.o doorrpc_xdr.o doorlibrary.o door.o
	$(LINK.c) -o $@ $^ -shared

libpkcs11rpc.so:	pkcs11_clnt.o pkcs11_xdr.o rpclibrary.o
	$(LINK.c) -o $@ $^ -shared

door.o:	doorrpc.h
doorlibrary.o: pkcs11.h
