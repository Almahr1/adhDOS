#include <stdio.h>

#if defined(__is_libk)
#include <kernel/serial.h>
#include <kernel/tty.h>
#endif

int putchar(int ic) {
#if defined(__is_libk)
  char c = (char)ic;
  terminal_write(&c, sizeof(c));

  if (serial_is_initialized(serial_get_output_port())) {
    serial_putchar(serial_get_output_port(), c);
  }
#else
  char c = (char)ic;
  asm volatile("movl $4, %%eax\n"
               "movl $1, %%ebx\n"
               "movl %0, %%ecx\n"
               "movl $1, %%edx\n"
               "int $0x80\n"
               :
               : "r"(&c)
               : "eax", "ebx", "ecx", "edx");
#endif
  return ic;
}
