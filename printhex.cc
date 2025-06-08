#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

void printhex(unsigned char *data, size_t len) {
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
}

char *stringhex(unsigned char *data, size_t len) {
	char *res = (char *)malloc(len * 3 + 1);

	for (int i = 0; i < len; i++)
    {
        sprintf(res + (i*3), "%02X ", data[i]);
    }

    res[len*3] = 0;

	return res;
}
