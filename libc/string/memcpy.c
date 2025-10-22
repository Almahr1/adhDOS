#include <string.h>

void *memcpy(void *__restrict dstptr, const void *__restrict srcptr, size_t size) {
    const unsigned char *src = (unsigned char *)srcptr;
    unsigned char *dst = (unsigned char *)dstptr;
    for (size_t i = 0; i < size; i++) {
        dst[i] = src[i];
    }
    return dstptr;
}
