#include <stdio.h>
#include <stdlib.h>

__attribute__((__noreturn__)) void abort(void) {
#if defined(__is_libk)
  // Kernel panic
  printf("KERNEL PANIC: abort() called\n");
  printf("System halted.\n");

  asm volatile("cli"); // Clear interrupt flag
  for (;;) {
    asm volatile("hlt");
  }
#else
  // TODO: Abnormally terminate the process as if by SIGABRT.
  printf("abort()\n");
  while (1) {
  }
#endif
  __builtin_unreachable();
}
