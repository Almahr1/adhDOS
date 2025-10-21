#ifndef _STRING_H
#define _STRING_H

#include <stddef.h>
#include <sys/cdefs.h> // The tutorial uses this for managing C/C++ compatibility.

#ifdef __cplusplus
extern "C"
{
#endif

  int memcmp (const void *aptr, const void *bptr, size_t size);
  void *memcpy (void *__restrict dstptr, const void *__restrict srcptr,
                size_t size);
  void *memmove (void *dstptr, const void *srcptr, size_t size);
  void *memset (void *bufptr, int value, size_t size);
  size_t strlen (const char *str);
  char *strcpy (char *dest, const char *src);
  char *strncpy (char *dest, const char *src, size_t n);

#ifdef __cplusplus
}
#endif

#endif
