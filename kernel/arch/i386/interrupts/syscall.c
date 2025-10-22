#include <kernel/gdt.h>
#include <kernel/idt.h>
#include <kernel/syscall.h>
#include <kernel/tty.h>
#include <stdio.h>

extern void syscall_entry(void);

static int sys_exit(int status) {
  printf("Process exit with status: %d\n", status);
  for (;;)
    asm volatile("hlt");
  return 0;
}

static int sys_write(int fd, const char *buf, size_t count) {
  if (fd == 1 || fd == 2) {
    for (size_t i = 0; i < count; i++) {
      terminal_putchar(buf[i]);
    }
    return count;
  }
  return -1;
}

static int sys_read(int fd, char *buf, size_t count) {
  (void)fd;
  (void)buf;
  (void)count;
  return -1;
}

void syscall_handler(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx,
                     uint32_t esi, uint32_t edi) {
  (void)esi;
  (void)edi;

  int ret = -1;

  switch (eax) {
  case SYSCALL_EXIT:
    ret = sys_exit((int)ebx);
    break;
  case SYSCALL_WRITE:
    ret = sys_write((int)ebx, (const char *)ecx, (size_t)edx);
    break;
  case SYSCALL_READ:
    ret = sys_read((int)ebx, (char *)ecx, (size_t)edx);
    break;
  default:
    printf("Unknown syscall: %d\n", eax);
    ret = -1;
    break;
  }

  asm volatile("movl %0, %%eax" ::"r"(ret));
}

void syscall_init(void) {
  idt_set_gate(0x80, (uint32_t)syscall_entry, KERNEL_CODE_SEGMENT,
               IDT_INT_GATE_USER);
  printf("System call handler installed (INT 0x80)\n");
}
