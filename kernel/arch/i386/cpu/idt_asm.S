#include "../asm_offsets.h"

.section .text

# Declare external C handlers
.extern isr_handler
.extern irq_handler

# ============================================================================
# ISR STUBS (CPU Exceptions 0-31)
# ============================================================================

# Common ISR stub - saves state and calls C handler
.globl isr_common_stub
.type isr_common_stub, @function
isr_common_stub:
    pusha                    # Push all general purpose registers

    mov %ds, %ax             # Save data segment
    push %eax

    mov $0x10, %ax           # Load kernel data segment
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    push %esp                # Pass pointer to registers struct
    call isr_handler         # Call C handler
    add $4, %esp             # Clean up parameter

    # Check if task switch was scheduled (next_task_ptr != NULL)
    .extern next_task_ptr
    mov (next_task_ptr), %eax   # EAX = Next Task Pointer
    test %eax, %eax
    jz .isr_no_switch

    # ---------------------------------------------------------
    # SAVE CURRENT TASK STATE
    # ---------------------------------------------------------
    .extern current_task
    mov (current_task), %edx    # EDX = Current Task Pointer
    test %edx, %edx
    jz .isr_load_next

    mov %esp, TASK_CONTEXT_ESP(%edx)  # Save ESP to current_task->context.esp

.isr_load_next:
    # ---------------------------------------------------------
    # SWITCH STACK
    # ---------------------------------------------------------
    mov TASK_CONTEXT_ESP(%eax), %esp  # Switch to new task's saved stack pointer

    # ---------------------------------------------------------
    # SWITCH ADDRESS SPACE (CR3)
    # ---------------------------------------------------------
    mov TASK_MM(%eax), %ecx           # ECX = task->mm
    test %ecx, %ecx                   # Safety check: is mm NULL?
    jz .isr_skip_cr3

    mov ADDRSPACE_PHYSICAL_ADDR(%ecx), %ecx  # ECX = mm->physical_addr
    mov %cr3, %edx           # EDX = Current CR3
    cmp %ecx, %edx           # Compare current vs new
    je .isr_skip_cr3         # If identical, skip reload (saves TLB flush)

    mov %ecx, %cr3           # Load new Page Directory (Flushes TLB)

.isr_skip_cr3:
    # ---------------------------------------------------------

    # Clear next_task_ptr to indicate switch is done
    movl $0, (next_task_ptr)

.isr_no_switch:
    pop %ebx                 # Restore data segment
    mov %bx, %ds
    mov %bx, %es
    mov %bx, %fs
    mov %bx, %gs

    popa                     # Restore registers
    add $8, %esp             # Clean up error code and interrupt number
    iret                     # Return from interrupt

# Macro for ISRs without error codes
.macro ISR_NOERRCODE num
    .globl isr\num
    .type isr\num, @function
    isr\num:
        cli                  # Disable interrupts
        push $0              # Push dummy error code
        push $\num           # Push interrupt number
        jmp isr_common_stub
.endm

# Macro for ISRs with error codes
.macro ISR_ERRCODE num
    .globl isr\num
    .type isr\num, @function
    isr\num:
        cli                  # Disable interrupts
        # CPU already pushed error code
        push $\num           # Push interrupt number
        jmp isr_common_stub
.endm

# Create all 32 ISR handlers for CPU exceptions
ISR_NOERRCODE 0   # Divide by Zero
ISR_NOERRCODE 1   # Debug
ISR_NOERRCODE 2   # Non-Maskable Interrupt
ISR_NOERRCODE 3   # Breakpoint
ISR_NOERRCODE 4   # Overflow
ISR_NOERRCODE 5   # Bound Range Exceeded
ISR_NOERRCODE 6   # Invalid Opcode
ISR_NOERRCODE 7   # Device Not Available
ISR_ERRCODE   8   # Double Fault (has error code)
ISR_NOERRCODE 9   # Coprocessor Segment Overrun
ISR_ERRCODE   10  # Invalid TSS (has error code)
ISR_ERRCODE   11  # Segment Not Present (has error code)
ISR_ERRCODE   12  # Stack-Segment Fault (has error code)
ISR_ERRCODE   13  # General Protection Fault (has error code)
ISR_ERRCODE   14  # Page Fault (has error code)
ISR_NOERRCODE 15  # Reserved
ISR_NOERRCODE 16  # x87 Floating-Point Exception
ISR_ERRCODE   17  # Alignment Check (has error code)
ISR_NOERRCODE 18  # Machine Check
ISR_NOERRCODE 19  # SIMD Floating-Point Exception
ISR_NOERRCODE 20  # Virtualization Exception
ISR_ERRCODE   21  # Control Protection Exception (has error code)
ISR_NOERRCODE 22  # Reserved
ISR_NOERRCODE 23  # Reserved
ISR_NOERRCODE 24  # Reserved
ISR_NOERRCODE 25  # Reserved
ISR_NOERRCODE 26  # Reserved
ISR_NOERRCODE 27  # Reserved
ISR_NOERRCODE 28  # Reserved
ISR_NOERRCODE 29  # Reserved
ISR_NOERRCODE 30  # Reserved
ISR_NOERRCODE 31  # Reserved

# ============================================================================
# SOFTWARE INTERRUPTS
# ============================================================================

# INT 0x80 (128) - System call / Yield interrupt
ISR_NOERRCODE 128

# ============================================================================
# IRQ STUBS (Hardware Interrupts 32-47)
# ============================================================================

# Common IRQ stub - saves state and calls C handler
.globl irq_common_stub
.type irq_common_stub, @function
irq_common_stub:
    pusha                    # Push all general purpose registers

    mov %ds, %ax             # Save data segment
    push %eax

    mov $0x10, %ax           # Load kernel data segment
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    push %esp                # Pass pointer to registers struct
    call irq_handler         # Call C handler
    add $4, %esp             # Clean up parameter

    # Check if task switch was scheduled
    .extern next_task_ptr
    mov (next_task_ptr), %eax   # EAX = Next Task Pointer
    test %eax, %eax
    jz .no_switch

    # ---------------------------------------------------------
    # SAVE CURRENT TASK STATE
    # ---------------------------------------------------------
    .extern current_task
    mov (current_task), %edx    # EDX = Current Task Pointer
    test %edx, %edx
    jz .irq_load_next

    mov %esp, TASK_CONTEXT_ESP(%edx)  # Save ESP to current_task->context.esp

.irq_load_next:
    # ---------------------------------------------------------
    # SWITCH STACK
    # ---------------------------------------------------------
    mov TASK_CONTEXT_ESP(%eax), %esp  # Switch to new task's saved stack pointer

    # ---------------------------------------------------------
    # SWITCH ADDRESS SPACE (CR3)
    # ---------------------------------------------------------
    mov TASK_MM(%eax), %ecx           # ECX = task->mm
    test %ecx, %ecx                   # Safety check
    jz .irq_skip_cr3

    mov ADDRSPACE_PHYSICAL_ADDR(%ecx), %ecx  # ECX = mm->physical_addr
    mov %cr3, %edx           # EDX = Current CR3
    cmp %ecx, %edx           # Compare current vs new
    je .irq_skip_cr3         # If identical, skip reload

    mov %ecx, %cr3           # Load new Page Directory (Flushes TLB)

.irq_skip_cr3:
    mov %eax, (current_task)

    # Clear next_task_ptr to indicate switch is done
    movl $0, (next_task_ptr)

.no_switch:
    pop %ebx                 # Restore data segment
    mov %bx, %ds
    mov %bx, %es
    mov %bx, %fs
    mov %bx, %gs

    popa                     # Restore registers
    add $8, %esp             # Clean up error code and IRQ number
    iret                     # Return from interrupt

# Macro to create IRQ stubs
.macro IRQ num, idt_num
    .globl irq\num
    .type irq\num, @function
    irq\num:
        cli                  # Disable interrupts
        push $0              # Dummy error code
        push $\idt_num       # Push interrupt number
        jmp irq_common_stub
.endm

# Create all 16 IRQ handlers
IRQ 0, 32    # Timer
IRQ 1, 33    # Keyboard
IRQ 2, 34    # Cascade
IRQ 3, 35    # COM2
IRQ 4, 36    # COM1
IRQ 5, 37    # LPT2
IRQ 6, 38    # Floppy disk
IRQ 7, 39    # LPT1
IRQ 8, 40    # CMOS real-time clock
IRQ 9, 41    # Free for peripherals
IRQ 10, 42   # Free for peripherals
IRQ 11, 43   # Free for peripherals
IRQ 12, 44   # PS/2 Mouse
IRQ 13, 45   # FPU
IRQ 14, 46   # Primary ATA
IRQ 15, 47   # Secondary ATA

# ============================================================================
# IDT Flush Function
# ============================================================================

.globl idt_flush
.type idt_flush, @function
idt_flush:
    mov 4(%esp), %eax        # Get the pointer to the IDT pointer
    lidt (%eax)              # Load the IDT
    ret
