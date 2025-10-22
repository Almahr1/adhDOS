#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>

#define SYSCALL_EXIT   1
#define SYSCALL_READ   3
#define SYSCALL_WRITE  4
#define SYSCALL_OPEN   5
#define SYSCALL_CLOSE  6

void syscall_init(void);
void syscall_handler(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx, uint32_t esi, uint32_t edi);

#endif
