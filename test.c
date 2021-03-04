#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "cryptoki_compat/pkcs11.h"

void setattr(CK_ATTRIBUTE* attr, unsigned long type, unsigned long size, unsigned char* value)
{
    long value8;
    attr->type = type;
    attr->ulValueLen = size;
    if(size == 0) {
        attr->pValue = NULL;
    } else {
        attr->pValue = malloc(size);
        if(value != NULL) {
            memcpy(attr->pValue, value, size);
        }
    }
}

unsigned char num0[] = { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char num1[] = { 0xcf, 0xb9, 0x90, 0x6d, 0xc0, 0x3e, 0x75, 0x67, 0x32, 0x06, 0x54, 0x0d, 0xa5, 0x4e, 0xd6, 0xcb };
unsigned char num2[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char num3[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
unsigned char num4[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

int
main(int argc, char* argv[])
{
    CK_FUNCTION_LIST_PTR pkcs11;
    unsigned long count;
    CK_SLOT_ID* slots;
    CK_TOKEN_INFO tokeninfo;
    CK_SESSION_HANDLE session;
    CK_SESSION_HANDLE session2;
    CK_SESSION_INFO sessioninfo;
    CK_ATTRIBUTE templ1[2];
    CK_ATTRIBUTE templ2[1];
    CK_OBJECT_HANDLE object;
    CK_OBJECT_HANDLE object2;
    unsigned long numobjects;

    /* dlopen("/home/berry/rpkcs/libpkcs11null.so", RTLD_NOW|RTLD_GLOBAL); */
    dlopen("/home/berry/workspace/root/OPENDNSSEC-721/lib/softhsm/libsofthsm2.so", RTLD_NOW|RTLD_GLOBAL);
    ((CK_C_GetFunctionList) dlsym(NULL, "C_GetFunctionList"))(&pkcs11);
    pkcs11->C_Initialize(NULL);
    pkcs11->C_GetSlotList(1,NULL,&count);
    slots = malloc(sizeof(CK_SLOT_ID)*count);
    pkcs11->C_GetSlotList(1,slots,&count);
    pkcs11->C_GetTokenInfo(slots[0], &tokeninfo);
    pkcs11->C_OpenSession(slots[0],6,NULL,0,&session);
    free(slots);
    pkcs11->C_Login(session,1,(unsigned char*)"1234",4);

    pkcs11->C_GetSlotList(1,NULL,&count);
    slots = malloc(sizeof(CK_SLOT_ID)*count);
    pkcs11->C_GetSlotList(1,slots,&count);
    pkcs11->C_GetTokenInfo(slots[0], &tokeninfo);
    pkcs11->C_OpenSession(slots[0],6,NULL,0,&session2);

    free(slots);

    setattr(&templ1[0],CKA_CLASS, 8, num0);
    setattr(&templ1[1],CKA_ID, 16, num1);
    pkcs11->C_FindObjectsInit(session2, templ1, sizeof(templ1)/sizeof(CK_ATTRIBUTE));
    pkcs11->C_FindObjects(session2, &object, 1, &numobjects);
    pkcs11->C_FindObjectsFinal(session2);
    setattr(&templ2[0], CKA_ID, 0, NULL);
    pkcs11->C_GetAttributeValue(session2, object, templ2, 1);
    setattr(&templ2[0], CKA_ID, templ2[0].ulValueLen, NULL);
    pkcs11->C_GetAttributeValue(session2, object, templ2, 1);

    setattr(&templ1[0],CKA_CLASS, 8, num2);
    setattr(&templ1[1],CKA_ID, 16, num3);
    pkcs11->C_FindObjectsInit(session2, templ1, sizeof(templ1)/sizeof(CK_ATTRIBUTE));
    pkcs11->C_FindObjects(session2, &object2, 1, &numobjects);
    pkcs11->C_FindObjectsFinal(session2);
    setattr(&templ2[0], CKA_KEY_TYPE, 8, num4);
    pkcs11->C_GetAttributeValue(session2, object, templ2, 1);
    setattr(&templ2[0], CKA_PRIME, 0, NULL);
    pkcs11->C_GetAttributeValue(session2, object, templ2, 1);
    setattr(&templ2[0], CKA_PRIME, templ2[0].ulValueLen, NULL);
    pkcs11->C_GetAttributeValue(session2, object, templ2, 1);

    pkcs11->C_CloseSession(session2);
    pkcs11->C_CloseSession(session);
    pkcs11->C_Finalize(NULL);
    printf("done\n");
    return (EXIT_SUCCESS);
}
#ifdef NOTDEFINED
FindObjectsInit(,,[{CKA_CLASS,[0200000000000000],8},{CKA_ID,[0100000000000000],8},,2)
FindObjects(,0x7f9fd6df4ad8,1,)
FindObjectsFinal()
GetAttributeValue(,,[{CKA_KEY_TYPE,,8},],1)
GetAttributeValue(,,[{CKA_PRIME,,0},{CKA_SUBPRIME,,0},{CKA_BASE,,0},{CKA_VALUE,,0},],4)
GetAttributeValue(,,[{CKA_PRIME,,8},{CKA_SUBPRIME,,8},{CKA_BASE,,8},{CKA_VALUE,,8},],4)
FindObjectsInit(,,[{CKA_CLASS,[0300000000000000],8},{CKA_ID,[802725771ccfc255e4145a9d8a12dc61],16},,2)
FindObjects(,0x7f9fd6df4b28,1,)
FindObjectsFinal()
GetAttributeValue(,,[{CKA_ID,,0},],1)
GetAttributeValue(,,[{CKA_ID,,8},],1)
FindObjectsInit(,,[{CKA_CLASS,[0200000000000000],8},{CKA_ID,[0100000000000000],8},,2)
FindObjects(,0x7f9fd6df4ad8,1,)
FindObjectsFinal()
GetAttributeValue(,,[{CKA_KEY_TYPE,,8},],1)
GetAttributeValue(,,[{CKA_PRIME,,0},{CKA_SUBPRIME,,0},{CKA_BASE,,0},{CKA_VALUE,,0},],4)
GetAttributeValue(,,[{CKA_PRIME,,8},{CKA_SUBPRIME,,8},{CKA_BASE,,8},{CKA_VALUE,,8},],4)
CloseSession()
GetSessionInfo()
OpenSession(0,6,,,)
CloseSession()
GetSlotList(1,,140320876527616)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
CloseSession()
GetSlotList(1,,4570894)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
CloseSession()
Logout()
CloseSession()
Finalize()
Initialize()
GetSlotList(1,,4224176)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
Login(,1,1234,4)
Logout()
CloseSession()
Finalize()



Initialize()
GetSlotList(1,,1485776480)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
Login(,1,1234,4)
GetSlotList(1,,0)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
FindObjectsInit(,,[{CKA_CLASS,[0300000000000000],8},{CKA_ID,[d827177e42e73c15792eb6cba997893c],16},,2)
FindObjects(,0x7f15e2886c18,1,)
FindObjectsFinal()
GetAttributeValue(,,[{CKA_ID,,0},],1)
GetAttributeValue(,,[{CKA_ID,,8},],1)
FindObjectsInit(,,[{CKA_CLASS,[0200000000000000],8},{CKA_ID,[0100000000000000],8},,2)
FindObjects(,0x7f15e2886bd8,1,)
FindObjectsFinal()
GetAttributeValue(,,[{CKA_KEY_TYPE,,8},],1)
GetAttributeValue(,,[{CKA_PRIME,,0},{CKA_SUBPRIME,,0},{CKA_BASE,,0},{CKA_VALUE,,0},],4)
GetAttributeValue(,,[{CKA_PRIME,,8},{CKA_SUBPRIME,,8},{CKA_BASE,,8},{CKA_VALUE,,8},],4)
FindObjectsInit(,,[{CKA_CLASS,[0300000000000000],8},{CKA_ID,[80c4d16a1e3ee1aa6f64fdbd87cee6d7],16},,2)
FindObjects(,0x7f15e2886c18,1,)
FindObjectsFinal()
GetAttributeValue(,,[{CKA_ID,,0},],1)
GetAttributeValue(,,[{CKA_ID,,8},],1)
FindObjectsInit(,,[{CKA_CLASS,[0200000000000000],8},{CKA_ID,[0100000000000000],8},,2)
FindObjects(,0x7f15e2886bd8,1,)
FindObjectsFinal()
GetAttributeValue(,,[{CKA_KEY_TYPE,,8},],1)
GetAttributeValue(,,[{CKA_PRIME,,0},{CKA_SUBPRIME,,0},{CKA_BASE,,0},{CKA_VALUE,,0},],4)
GetAttributeValue(,,[{CKA_PRIME,,8},{CKA_SUBPRIME,,8},{CKA_BASE,,8},{CKA_VALUE,,8},],4)
CloseSession()
GetSessionInfo()
OpenSession(0,6,,,)
CloseSession()
GetSlotList(1,,139731971635648)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
CloseSession()
GetSlotList(1,,0)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
GetSlotList(1,,0)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
GetSlotList(1,,0)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
GetSlotList(1,,0)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
SignInit(,{1,,0},)
Sign(,,35,,512)
Sign(,,35,,512)
SignInit(,{1,,0},)
SignInit(,{1,Sign(,,35,,512)
,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
SignInit(,{1,Sign(,,35,,512)
,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,SignInit(,{1,,0},)
,0},)
Sign(,,35,,512)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,SignInit(,{1,,0},)
,0},)
Sign(,,35,,512)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
SignInit(,{1,Sign(,,35,,512)
,0},)
SignInit(,{1,Sign(,,35,,512)
,0},)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
SignInit(,{1,SignInit(,{1,,0},)
,0},)
Sign(,,35,,512)
Sign(,,35,,512)
SignInit(,{1,,0},)
Sign(,,35,,512)
CloseSession()
CloseSession()
CloseSession()
CloseSession()
Logout()
CloseSession()
Finalize()
Initialize()
GetSlotList(1,,1485776480)
GetSlotList(1,,1)
GetTokenInfo(0,)
OpenSession(0,6,,,)
Login(,1,1234,4)
Logout()
CloseSession()
Finalize()
#endif