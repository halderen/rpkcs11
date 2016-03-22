#include <stdio.h>
#include "cryptoki_compat/pkcs11.h"

unsigned long checksum(unsigned char* data, unsigned long len) {
    unsigned long check = 0;
    int i;
    for (i = 0; i < len; i++)
        check += data[i];
    return check;
}

void
printtemplate(CK_ATTRIBUTE* templ, unsigned long count)
{
    int i, j;
    int ptr;
    printf("template at %p with %lu entries\n",templ,count);
    for(i=0; i<count; i++) {
        printf("  %lu %lu %lu\n", templ[i].type, templ[i].ulValueLen, checksum(templ[i].pValue, templ[i].ulValueLen));
    }
}
