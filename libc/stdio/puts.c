#include <stdio.h>

int puts(const char *string) {
  while (*string) {
    if (putchar(*string++) == EOF)
      return EOF;
  }
  if (putchar('\n') == EOF)
    return EOF;
  return 0;
}
