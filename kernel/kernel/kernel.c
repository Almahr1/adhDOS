#include <kernel/gdt.h>
#include <kernel/idt.h>
#include <kernel/keyboard.h>
#include <kernel/memory.h>
#include <kernel/paging.h>
#include <kernel/pic.h>
#include <kernel/process.h>
#include <kernel/sched.h>
#include <kernel/serial.h>
#include <kernel/tty.h>
#include <stdio.h>

// Arbitrary virtual address for testing
#define SHARED_VIRTUAL_ADDR 0x50000000

void test_task_1(void) {
  printf("Task 1: Monitor started.\n");
  int loop_count = 0;
  
  while (1) {
    printf("\n--- Monitor Check %d ---\n", loop_count++);
    
    // Print the process table to see who is alive/dead
    process_print_all(); 

    // Delay loop so it doesn't spam the console too fast
    for (volatile int i = 0; i < 5000000; i++);
  }
}

void test_task_2(void) {
  printf("Task 2: Started. I will live for 3 loops, then exit.\n");

  for (int i = 1; i <= 3; i++) {
    printf("Task 2: Loop %d of 3...\n", i);
    
    // Delay loop
    for (volatile int j = 0; j < 5000000; j++);
  }

  printf("Task 2: Calling process_exit(123) now!\n");
  
  // This triggers the TASK_ZOMBIE state and halts the task
  process_exit(123); 
}

void kernel_main(multiboot_info_t *mboot_info) {
  serial_init(COM1, SERIAL_BAUD_115200);
  serial_set_output_port(COM1);

  gdt_init();
  idt_init();
  terminal_initialize();
  keyboard_init();
  memory_init(mboot_info);
  paging_init();

  pic_enable_irq(0);
  pic_enable_irq(1);

  asm volatile("sti");

  printf("adhDOS Kernel: Initializing Multitasking...\n");

  scheduler_init();
  process_init();

  task_t *t1 = process_create("monitor", test_task_1, 0);
  task_t *t2 = process_create("doomed", test_task_2, 0);

  printf("Starting scheduler. Watch the process table!\n");

  for (;;) {
    asm volatile("hlt");
  }
}
