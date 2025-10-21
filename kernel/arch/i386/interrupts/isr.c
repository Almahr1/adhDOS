#include <kernel/idt.h>
#include <kernel/keyboard.h>
#include <stdint.h>
#include <stdio.h>

// Saved register state from assembly stub
struct registers {
  uint32_t ds;                                     // Data segment
  uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax; // Pushed by pusha
  uint32_t int_no, err_code;             // Interrupt number and error code
  uint32_t eip, cs, eflags, useresp, ss; // Pushed by processor
};

// Exception names
static const char *exception_messages[] = {"Division By Zero",
                                           "Debug",
                                           "Non Maskable Interrupt",
                                           "Breakpoint",
                                           "Overflow",
                                           "Bound Range Exceeded",
                                           "Invalid Opcode",
                                           "Device Not Available",
                                           "Double Fault",
                                           "Coprocessor Segment Overrun",
                                           "Invalid TSS",
                                           "Segment Not Present",
                                           "Stack-Segment Fault",
                                           "General Protection Fault",
                                           "Page Fault",
                                           "Reserved",
                                           "x87 Floating-Point Exception",
                                           "Alignment Check",
                                           "Machine Check",
                                           "SIMD Floating-Point Exception",
                                           "Virtualization Exception",
                                           "Control Protection Exception",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved",
                                           "Reserved"};

// Global tick counter
static volatile uint32_t timer_ticks = 0;

// ISR handler - called from assembly for CPU exceptions
void isr_handler(struct registers regs) {
  if (regs.int_no < 32) {
    printf("Exception: %s (INT %d)\n", exception_messages[regs.int_no],
           regs.int_no);

    if (regs.err_code != 0) {
      printf("Error Code: 0x%x\n", regs.err_code);
    }

    printf("EIP: 0x%x, CS: 0x%x, EFLAGS: 0x%x\n", regs.eip, regs.cs,
           regs.eflags);

    // Halt the system on unhandled exception
    for (;;) {
      asm volatile("hlt");
    }
  }
}

// IRQ handler - called from assembly
void irq_handler(struct registers regs) {
  uint8_t irq_num = regs.int_no - 32; // Convert to IRQ number (0-15)

  // Handle specific IRQs
  switch (irq_num) {
  case 0: // Timer (IRQ 0)
    timer_ticks++;
    // Print every 100 ticks (approximately 1 second at 18.2 Hz)
    if (timer_ticks % 100 == 0) {
      printf("Timer tick: %d\n", timer_ticks);
    }
    break;

  case 1: // Keyboard (IRQ 1)
    keyboard_handle_interrupt();
    break;

  default:
    printf("IRQ %d received\n", irq_num);
    break;
  }

  // Send End of Interrupt (EOI) to PICs
  if (regs.int_no >= 40) {
    // Send reset signal to slave PIC for IRQs 8-15
    asm volatile("outb %0, %1" : : "a"((uint8_t)0x20), "Nd"((uint16_t)0xA0));
  }
  // Always send reset signal to master PIC
  asm volatile("outb %0, %1" : : "a"((uint8_t)0x20), "Nd"((uint16_t)0x20));
}

// Get current timer ticks
uint32_t timer_get_ticks(void) { return timer_ticks; }
