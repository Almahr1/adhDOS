#include <kernel/gdt.h>
#include <kernel/idt.h>
#include <kernel/pic.h>
#include <stdint.h>
#include <string.h>

#define IDT_ENTRIES 256

static struct idt_entry idt_entries[IDT_ENTRIES];
static struct idt_ptr idt_pointer;

// Defined in idt_asm.S
extern void idt_flush(uint32_t);

void idt_set_gate(uint8_t num, uint32_t base, uint16_t selector,
                  uint8_t flags) {
  idt_entries[num].base_low = base & 0xFFFF;
  idt_entries[num].base_high = (base >> 16) & 0xFFFF;

  idt_entries[num].selector = selector;
  idt_entries[num].always0 = 0;
  idt_entries[num].flags = flags;
}

void idt_init(void) {
  idt_pointer.limit = (sizeof(struct idt_entry) * IDT_ENTRIES) - 1;
  idt_pointer.base = (uint32_t)&idt_entries;

  // Clear the IDT
  memset(&idt_entries, 0, sizeof(struct idt_entry) * IDT_ENTRIES);

  // Remap the PIC before setting the irq handlers
  pic_init();

  // Install CPU exception handlers (ISRs 0-31)
  idt_set_gate(0, (uint32_t)isr0, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(1, (uint32_t)isr1, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(2, (uint32_t)isr2, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(3, (uint32_t)isr3, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(4, (uint32_t)isr4, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(5, (uint32_t)isr5, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(6, (uint32_t)isr6, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(7, (uint32_t)isr7, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(8, (uint32_t)isr8, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(9, (uint32_t)isr9, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(10, (uint32_t)isr10, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(11, (uint32_t)isr11, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(12, (uint32_t)isr12, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(13, (uint32_t)isr13, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(14, (uint32_t)isr14, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(15, (uint32_t)isr15, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(16, (uint32_t)isr16, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(17, (uint32_t)isr17, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(18, (uint32_t)isr18, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(19, (uint32_t)isr19, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(20, (uint32_t)isr20, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(21, (uint32_t)isr21, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(22, (uint32_t)isr22, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(23, (uint32_t)isr23, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(24, (uint32_t)isr24, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(25, (uint32_t)isr25, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(26, (uint32_t)isr26, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(27, (uint32_t)isr27, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(28, (uint32_t)isr28, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(29, (uint32_t)isr29, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(30, (uint32_t)isr30, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(31, (uint32_t)isr31, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);

  // Install IRQ handlers (remapped to 32-47)
  idt_set_gate(32, (uint32_t)irq0, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(33, (uint32_t)irq1, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(34, (uint32_t)irq2, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(35, (uint32_t)irq3, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(36, (uint32_t)irq4, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(37, (uint32_t)irq5, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(38, (uint32_t)irq6, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(39, (uint32_t)irq7, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(40, (uint32_t)irq8, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(41, (uint32_t)irq9, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(42, (uint32_t)irq10, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(43, (uint32_t)irq11, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(44, (uint32_t)irq12, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(45, (uint32_t)irq13, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(46, (uint32_t)irq14, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);
  idt_set_gate(47, (uint32_t)irq15, KERNEL_CODE_SEGMENT, IDT_INT_GATE_32);

  // Load the IDT
  idt_flush((uint32_t)&idt_pointer);
}
