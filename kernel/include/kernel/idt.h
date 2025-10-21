#ifndef IDT_H
#define IDT_H

#ifndef __ASSEMBLER__
#include <stdint.h>

// IDT entry structure
struct idt_entry {
    uint16_t base_low;      // Lower 16 bits of handler address
    uint16_t selector;      // Kernel segment selector
    uint8_t  always0;       // Always zero
    uint8_t  flags;         // Flags (gate type, DPL, P)
    uint16_t base_high;     // Upper 16 bits of handler address
} __attribute__((packed));

// IDT pointer structure
struct idt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

// IDT flags
#define IDT_FLAG_PRESENT     0x80   // Present bit
#define IDT_FLAG_RING0       0x00   // Ring 0 (kernel)
#define IDT_FLAG_RING3       0x60   // Ring 3 (user)
#define IDT_FLAG_GATE_TASK   0x05   // Task gate
#define IDT_FLAG_GATE_16INT  0x06   // 16-bit interrupt gate
#define IDT_FLAG_GATE_16TRAP 0x07   // 16-bit trap gate
#define IDT_FLAG_GATE_32INT  0x0E   // 32-bit interrupt gate
#define IDT_FLAG_GATE_32TRAP 0x0F   // 32-bit trap gate

// Common flag combinations
#define IDT_INT_GATE_32  (IDT_FLAG_PRESENT | IDT_FLAG_RING0 | IDT_FLAG_GATE_32INT)
#define IDT_TRAP_GATE_32 (IDT_FLAG_PRESENT | IDT_FLAG_RING0 | IDT_FLAG_GATE_32TRAP)
#define IDT_INT_GATE_USER (IDT_FLAG_PRESENT | IDT_FLAG_RING3 | IDT_FLAG_GATE_32INT)

// Functions
void idt_init(void);
void idt_set_gate(uint8_t num, uint32_t base, uint16_t selector, uint8_t flags);

// Exception handlers (declared in isr.c)
extern void isr0(void);   // Division By Zero
extern void isr1(void);   // Debug
extern void isr2(void);   // Non Maskable Interrupt
extern void isr3(void);   // Breakpoint
extern void isr4(void);   // Overflow
extern void isr5(void);   // Bound Range Exceeded
extern void isr6(void);   // Invalid Opcode
extern void isr7(void);   // Device Not Available
extern void isr8(void);   // Double Fault
extern void isr9(void);   // Coprocessor Segment Overrun
extern void isr10(void);  // Invalid TSS
extern void isr11(void);  // Segment Not Present
extern void isr12(void);  // Stack-Segment Fault
extern void isr13(void);  // General Protection Fault
extern void isr14(void);  // Page Fault
extern void isr15(void);  // Reserved
extern void isr16(void);  // x87 Floating-Point Exception
extern void isr17(void);  // Alignment Check
extern void isr18(void);  // Machine Check
extern void isr19(void);  // SIMD Floating-Point Exception
extern void isr20(void);  // Virtualization Exception
extern void isr21(void);  // Control Protection Exception
extern void isr22(void);  // Reserved
extern void isr23(void);  // Reserved
extern void isr24(void);  // Reserved
extern void isr25(void);  // Reserved
extern void isr26(void);  // Reserved
extern void isr27(void);  // Reserved
extern void isr28(void);  // Reserved
extern void isr29(void);  // Reserved
extern void isr30(void);  // Reserved
extern void isr31(void);  // Reserved

// IRQ handlers (hardware interrupts - declared in isr.c)
extern void irq0(void);   // Timer
extern void irq1(void);   // Keyboard
extern void irq2(void);   // Cascade
extern void irq3(void);   // COM2
extern void irq4(void);   // COM1
extern void irq5(void);   // LPT2
extern void irq6(void);   // Floppy
extern void irq7(void);   // LPT1
extern void irq8(void);   // CMOS Real-time clock
extern void irq9(void);   // Free
extern void irq10(void);  // Free
extern void irq11(void);  // Free
extern void irq12(void);  // PS2 Mouse
extern void irq13(void);  // FPU
extern void irq14(void);  // Primary ATA
extern void irq15(void);  // Secondary ATA

#endif /* __ASSEMBLER__ */

// Exception/Interrupt numbers (can be used in assembly)
#define INT_DIVIDE_ERROR        0
#define INT_DEBUG               1
#define INT_NMI                 2
#define INT_BREAKPOINT          3
#define INT_OVERFLOW            4
#define INT_BOUND_RANGE         5
#define INT_INVALID_OPCODE      6
#define INT_DEVICE_NOT_AVAIL    7
#define INT_DOUBLE_FAULT        8
#define INT_INVALID_TSS         10
#define INT_SEGMENT_NOT_PRESENT 11
#define INT_STACK_FAULT         12
#define INT_GENERAL_PROTECTION  13
#define INT_PAGE_FAULT          14

// IRQs (remapped to 32-47)
#define IRQ_BASE    32
#define IRQ_TIMER   (IRQ_BASE + 0)
#define IRQ_KEYBOARD (IRQ_BASE + 1)

#endif /* IDT_H */
