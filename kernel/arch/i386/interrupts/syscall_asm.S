.section .text
.extern syscall_handler

.globl syscall_entry
.type syscall_entry, @function
syscall_entry:
    cli

    pushl %ebp
    pushl %edi
    pushl %esi
    pushl %edx
    pushl %ecx
    pushl %ebx
    pushl %eax

    push %edi
    push %esi
    push %edx
    push %ecx
    push %ebx
    push %eax

    call syscall_handler

    add $24, %esp

    popl %ebx
    popl %ebx
    popl %ecx
    popl %edx
    popl %esi
    popl %edi
    popl %ebp

    sti
    iret
