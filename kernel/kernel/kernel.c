#include <kernel/gdt.h>
#include <kernel/idt.h>
#include <kernel/keyboard.h>
#include <kernel/memory.h>
#include <kernel/pic.h>
#include <kernel/tty.h>
#include <stdio.h>

void kernel_main(multiboot_info_t *mboot_info) {
  gdt_init();
  idt_init();
  terminal_initialize();
  keyboard_init();
  memory_init(mboot_info);

  // unmask IRQs we wanna handle
  pic_enable_irq(0); // Enable Timer
  pic_enable_irq(1); // Enable Keyboard

  // Enable interrupts in the CPU
  asm volatile("sti"); // Set Interrupt flag

  printf("Running comprehensive memory tests...\n");
  bool tests_passed = memory_run_tests();
  
  if (tests_passed) {
    printf("All memory tests passed! System is stable.\n");
  } else {
    printf("WARNING: Some memory tests failed!\n");
  }
  
  memory_print_caches();
  memory_print_stats();
  memory_print_leaks();
  
  printf("adhDOS kernel ready - type on keyboard to test input!");

  // Halt the system
  for (;;) {
    asm volatile("hlt");
  }
}
