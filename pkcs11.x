#ifdef RPC_HDR
%#include <stdlib.h>
%#include "cryptoki_compat/pkcs11.h"
%typedef struct { CK_ATTRIBUTE* attr; unsigned long count; } attributes;
%void returnattributes(CK_ATTRIBUTE* templ, unsigned long count, attributes attrs);
%void duplicateattributes(attributes* dest, attributes attrs);
#endif

#ifdef RPC_XDR
%bool_t
%xdr_attributes(XDR* xdrs, attributes* attrs)
%{
%    unsigned long i;
%    bool_t nullptr;
%
%    xdr_u_long(xdrs, &attrs->count);
%    if(xdrs->x_op == XDR_DECODE) {
%        if((attrs->attr = malloc(sizeof(CK_ATTRIBUTE) * attrs->count)) == NULL) {
%            return FALSE;
%        }
%    }
%    for(i=0; i<attrs->count; i++) {
%        if(!xdr_u_long(xdrs, &attrs->attr[i].type)) {
%            return FALSE;
%        }
%        if(xdrs->x_op == XDR_ENCODE) {
%            nullptr = (attrs->attr[i].pValue == NULL);
%        }
%        if(!xdr_bool(xdrs, &nullptr)) {
%            return FALSE;
%        }
%        if(!xdr_u_long(xdrs, &attrs->attr[i].ulValueLen)) {
%            return FALSE;
%        }
%        if(!nullptr) {
%            if(xdrs->x_op == XDR_DECODE) {
%                attrs->attr[i].pValue = malloc(attrs->attr[i].ulValueLen);
%             } else if(xdrs->x_op == XDR_FREE) {
%                free(attrs->attr[i].pValue);
%             }
%            if(!xdr_opaque(xdrs, attrs->attr[i].pValue, attrs->attr[i].ulValueLen)) {
%                    return FALSE;
%            }
%        } else
%            attrs->attr[i].pValue = NULL;
%    }
%    return TRUE;
%}
%
%void
%returnattributes(CK_ATTRIBUTE* templ, unsigned long count, attributes attrs)
%{
%    unsigned long i;
%    size_t size;
%    if(attrs.count < count)
%        count = attrs.count;
%    for(i=0; i<count; i++) {
%        if(templ[i].pValue != NULL) {
%            size = (templ[i].ulValueLen < attrs.attr[i].ulValueLen ? templ[i].ulValueLen : attrs.attr[i].ulValueLen);
%            memcpy(templ[i].pValue, attrs.attr[i].pValue, size);
%        }
%        templ[i].ulValueLen = attrs.attr[i].ulValueLen;
%    }
%}
%void duplicateattributes(attributes* dest, attributes attrs)
%{
%    unsigned long i;
%    dest->count = attrs.count;
%    dest->attr = malloc(sizeof(CK_ATTRIBUTE) * attrs.count);
%    for(i=0; i<attrs.count; i++) {
%        dest->attr[i] = attrs.attr[i];
%        if(attrs.attr[i].pValue) {
%            dest->attr[i].pValue = malloc(attrs.attr[i].ulValueLen);
%            memcpy(dest->attr[i].pValue, attrs.attr[i].pValue, attrs.attr[i].ulValueLen);
%        }
%    }
%}
#endif

struct versioninfo
{
  unsigned char major;
  unsigned char minor;
};

struct info
{
  struct versioninfo cryptoki_version;
  unsigned char manufacturer_id[32];
  unsigned long flags;
  unsigned char library_description[32];
  struct versioninfo library_version;
  unsigned long result;
};

struct slot_info
{
  unsigned char slot_description[64];
  unsigned char manufacturer_id[32];
  unsigned long flags;
  struct versioninfo hardware_version;
  struct versioninfo firmware_version;
  unsigned long result;
};

struct token_info
{
  unsigned char label[32];
  unsigned char manufacturer_id[32];
  unsigned char model[16];
  unsigned char serial_number[16];
  unsigned long flags;
  unsigned long max_session_count;
  unsigned long session_count;
  unsigned long max_rw_session_count;
  unsigned long rw_session_count;
  unsigned long max_pin_len;
  unsigned long min_pin_len;
  unsigned long total_public_memory;
  unsigned long free_public_memory;
  unsigned long total_private_memory;
  unsigned long free_private_memory;
  struct versioninfo hardware_version;
  struct versioninfo firmware_version;
  unsigned char utc_time[16];
  unsigned long result;
};

struct session_info
{
  unsigned long slot_id;
  unsigned long state;
  unsigned long flags;
  unsigned long device_error;
  unsigned long result;
};

struct attributesresult
{
    attributes template;
    int actualcount;
    unsigned long result;
};

struct date
{
  unsigned char year[4];
  unsigned char month[2];
  unsigned char day[2];
};

struct mechanism
{
  unsigned long mechanism;
  opaque parameter<>;
};

struct slotlist
{
    unsigned long slots<>;
    unsigned long actualcount;
    unsigned long result;
};
struct sessionresult
{
    unsigned long session;
    unsigned long result;
};

struct objectsresult
{
    unsigned long objects<>;
    unsigned long actualcount;
    unsigned long result;
};

struct digestresult
{
    opaque digest<>;
    unsigned long actuallen;
    unsigned long result;
};

struct keyresult
{
    unsigned long key;
    unsigned long result;
};

struct keypairresult
{
    unsigned long public_key;
    unsigned long private_key;
    unsigned long result;
};

struct dataresult
{
    opaque data<>;
    unsigned long actuallen;
    unsigned long result;
};

struct randomresult
{
    opaque data<>;
    unsigned long result;
};

typedef opaque data<>;

program PKCSPROG {
	version PKCSVERS {
		void                PKCSPROC_NULL(void)                                                          =  0;
		unsigned long       PKCSPROC_INITIALIZE()                                                        =  1;
		unsigned long       PKCSPROC_FINALIZE()                                                          =  2;
		info                PKCSPROC_GETINFO()                                                           =  3;
		slotlist            PKCSPROC_GETSLOTLIST(unsigned char token_present, unsigned long maxcount)    =  5;
		slot_info           PKCSPROC_GETSLOTINFO(unsigned long slot_id)                                  =  6;
		token_info          PKCSPROC_GETTOKENINFO(unsigned long slot_id)                                 =  7;
		sessionresult       PKCSPROC_OPENSESSION(unsigned long slot_id, unsigned long flags)             = 14;
		unsigned long       PKCSPROC_CLOSESESSION(unsigned long session)                                 = 15;
		session_info        PKCSPROC_GETSESSIONINFO(unsigned long session)                               = 17;
		unsigned long       PKCSPROC_LOGIN(unsigned long session, unsigned long user_type, data pin) = 20;
		unsigned long       PKCSPROC_LOGOUT(unsigned long session) = 21;
		unsigned long       PKCSPROC_DESTROYOBJECT(unsigned long session, unsigned long object) = 24;
		attributesresult    PKCSPROC_GETATTRIBUTEVALUE(unsigned long session, unsigned long object, attributes template) = 26;
		unsigned long       PKCSPROC_FINDOBJECTSINIT(unsigned long session, attributes template) = 28;
		objectsresult       PKCSPROC_FINDOBJECTS(unsigned long session, unsigned long maxcount) = 29;
		unsigned long       PKCSPROC_FINDOBJECTSFINAL(unsigned long session) = 30;
		unsigned long       PKCSPROC_DIGESTINIT(unsigned long session, mechanism mechanism) = 39;
		dataresult          PKCSPROC_DIGEST(unsigned long session, data plain, unsigned long digest_len) = 40;
		unsigned long       PKCSPROC_SIGNINIT(unsigned long session, mechanism mechanism, unsigned long key) = 44;
		dataresult          PKCSPROC_SIGN(unsigned long session, data plain, unsigned long signature_len) = 45;
		keyresult           PKCSPROC_GENERATEKEY(unsigned long session, mechanism mechanism, attributes template) = 60;
		keypairresult       PKCSPROC_GENERATEKEYPAIR(unsigned long session, mechanism mechanism, attributes public_key_template, attributes private_key_template) = 61;
		unsigned long       PKCSPROC_SEEDRANDOM(unsigned long session, data seed) = 65;
		randomresult        PKCSPROC_GENERATERANDOM(unsigned long session, unsigned long length) = 66;
	} = 1;
} = 200492;
