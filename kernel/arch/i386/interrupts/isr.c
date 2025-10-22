#include <kernel/idt.h>
#include <kernel/keyboard.h>
#include <kernel/paging.h>
#include <stdint.h>
#include <stdio.h>

struct registers {
  uint32_t ds;
  uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
  uint32_t int_no, err_code;
  uint32_t eip, cs, eflags, useresp, ss;
};

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

static volatile uint32_t timer_ticks = 0;

void isr_handler(struct registers regs) {
  if (regs.int_no == 14) {
    uint32_t faulting_addr;
    asm volatile("mov %%cr2, %0" : "=r"(faulting_addr));
    page_fault_handler(regs.err_code, faulting_addr);
    return;
  }

  if (regs.int_no < 32) {
    printf("Exception: %s (INT %d)\n", exception_messages[regs.int_no],
           regs.int_no);

    if (regs.err_code != 0) {
      printf("Error Code: 0x%x\n", regs.err_code);
    }

    printf("EIP: 0x%08x, CS: 0x%x, EFLAGS: 0x%08x\n", regs.eip, regs.cs,
           regs.eflags);

    for (;;) {
      asm volatile("hlt");
    }
  }
}

void irq_handler(struct registers regs) {
  uint8_t irq_num = regs.int_no - 32;

  switch (irq_num) {
  case 0:
    timer_ticks++;
    if (timer_ticks % 100 == 0) {
      printf("Timer tick: %d\n", timer_ticks);
    }
    break;

  case 1:
    keyboard_handle_interrupt();
    break;

  default:
    printf("IRQ %d received\n", irq_num);
    break;
  }

  if (regs.int_no >= 40) {
    asm volatile("outb %0, %1" : : "a"((uint8_t)0x20), "Nd"((uint16_t)0xA0));
  }
  asm volatile("outb %0, %1" : : "a"((uint8_t)0x20), "Nd"((uint16_t)0x20));
}

uint32_t timer_get_ticks(void) { return timer_ticks; }
