#include <kernel/gdt.h>
#include <kernel/idt.h>
#include <kernel/keyboard.h>
#include <kernel/memory.h>
#include <kernel/paging.h>
#include <kernel/pic.h>
#include <kernel/serial.h>
#include <kernel/tty.h>
#include <stdio.h>

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

  printf("\n=== Testing paging system ===\n");
  address_space_t *test_space = paging_create_address_space();
  if (test_space) {
    printf("Created new address space at 0x%08x\n", test_space->physical_addr);

    uint32_t test_phys = pmm_alloc_page();
    if (test_phys) {
      printf("Mapping virtual 0x40000000 -> physical 0x%08x\n", test_phys);
      paging_map_page(test_space, 0x40000000, test_phys,
                      PAGE_PRESENT | PAGE_WRITE | PAGE_USER);

      uint32_t resolved = paging_get_physical(test_space, 0x40000000);
      printf("Resolved physical address: 0x%08x\n", resolved);

      if (resolved == test_phys) {
        printf("Paging test PASSED!\n");
      } else {
        printf("Paging test FAILED!\n");
      }

      paging_unmap_page(test_space, 0x40000000);
      pmm_free_page(test_phys);
    }

    paging_destroy_address_space(test_space);
    printf("Destroyed test address space\n");
  }

  printf("\nadhDOS kernel ready - type on keyboard to test input!\n");
  printf("Serial output on COM1 at 115200 baud\n");

  for (;;) {
    asm volatile("hlt");
  }
}
