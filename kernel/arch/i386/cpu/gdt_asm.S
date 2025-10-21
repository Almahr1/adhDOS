#include <kernel/gdt.h>  /* Include the header to use the selector macros */

.section .text
.global gdt_flush        /* Makes gdt_flush visible to C */
.type gdt_flush, @function

gdt_flush:
    movl 4(%esp), %eax      /* Get the GDT pointer from the stack */
    lgdt (%eax)             /* Load the GDT */

    /* Reload all data segment registers with the Kernel Data Segment selector */
    movw $KERNEL_DATA_SEGMENT, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* Perform a far jump to reload the CS register */
    /* This jumps to the Kernel Code Segment selector */
    jmp $KERNEL_CODE_SEGMENT, $.flush_cs

.flush_cs:
    ret
