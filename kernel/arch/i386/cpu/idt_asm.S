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

    call isr_handler         # Call C handler

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

    call irq_handler         # Call C handler

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

# Create all 16 IRQ handlers (IRQ 0-15 mapped to vectors 32-47)
IRQ 0, 32    # Timer
IRQ 1, 33    # Keyboard
IRQ 2, 34    # Cascade (never raised)
IRQ 3, 35    # COM2
IRQ 4, 36    # COM1
IRQ 5, 37    # LPT2
IRQ 6, 38    # Floppy disk
IRQ 7, 39    # LPT1
IRQ 8, 40    # CMOS real-time clock
IRQ 9, 41    # Free for peripherals / legacy SCSI / NIC
IRQ 10, 42   # Free for peripherals / SCSI / NIC
IRQ 11, 43   # Free for peripherals / SCSI / NIC
IRQ 12, 44   # PS/2 Mouse
IRQ 13, 45   # FPU / Coprocessor / Inter-processor
IRQ 14, 46   # Primary ATA Hard Disk
IRQ 15, 47   # Secondary ATA Hard Disk

# ============================================================================
# IDT Flush Function
# ============================================================================

.globl idt_flush
.type idt_flush, @function
idt_flush:
    mov 4(%esp), %eax        # Get the pointer to the IDT pointer
    lidt (%eax)              # Load the IDT
    ret
