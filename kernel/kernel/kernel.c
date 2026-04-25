#include <kernel/gdt.h>
#include <kernel/idt.h>
#include <kernel/keyboard.h>
#include <kernel/memory.h>
#include <kernel/multiboot.h>
#include <kernel/paging.h>
#include <kernel/pic.h>
#include <kernel/process.h>
#include <kernel/sched.h>
#include <kernel/serial.h>
#include <kernel/syscall.h>
#include <kernel/tty.h>
#include <stdio.h>

void test_task_1(void) {
  printf("Task 1: Monitor started.\n");
  int loop_count = 0;

  while (1) {
    printf("\n--- Monitor Check %d ---\n", loop_count++);
    process_print_all();
    for (volatile int i = 0; i < 5000000; i++);
  }
}

void test_task_2(void) {
  printf("Task 2: Started. I will live for 3 loops, then exit.\n");

  for (int i = 1; i <= 3; i++) {
    printf("Task 2: Loop %d of 3...\n", i);
    for (volatile int j = 0; j < 25000; j++);
  }

  printf("Task 2: Calling process_exit(123) now!\n");
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
  syscall_init();

  task_t *t1 = process_create("monitor", test_task_1, 0);
  task_t *t2 = process_create("doomed", test_task_2, 0);
  (void)t1;
  (void)t2;

  if ((mboot_info->flags & MULTIBOOT_FLAG_MODS) && mboot_info->mods_count > 0) {
    multiboot_module_t *mod = (multiboot_module_t *)mboot_info->mods_addr;
    uint32_t mod_size = mod->mod_end - mod->mod_start;
    uint32_t mod_pages = (mod_size + PAGE_SIZE - 1) / PAGE_SIZE;

    printf("Loading user binary: %d bytes at phys 0x%08x\n", mod_size, mod->mod_start);

    task_t *user_task = process_create_user("hello", USER_CODE_VA, 0);
    if (user_task) {
      for (uint32_t i = 0; i < mod_pages; i++) {
        paging_map_page(user_task->mm,
                        USER_CODE_VA + i * PAGE_SIZE,
                        mod->mod_start + i * PAGE_SIZE,
                        PAGE_PRESENT | PAGE_USER);
      }
      printf("User task created: PID %d, entry 0x%08x\n", user_task->pid, USER_CODE_VA);
    }
  } else {
    printf("No multiboot modules found — skipping user task\n");
  }

  printf("Starting scheduler.\n");

  for (;;) {
    asm volatile("hlt");
  }
}
