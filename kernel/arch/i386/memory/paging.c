#include <kernel/memory.h>
#include <kernel/paging.h>
#include <stdio.h>
#include <string.h>

static address_space_t kernel_space;
static address_space_t *current_space = NULL;

extern uint32_t kernel_end;

static void flush_tlb_single(uint32_t addr) {
  asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
}

static void enable_paging(uint32_t page_directory_physical) {
  asm volatile("mov %0, %%cr3" ::"r"(page_directory_physical));

  uint32_t cr0;
  asm volatile("mov %%cr0, %0" : "=r"(cr0));
  cr0 |= 0x80000000;
  asm volatile("mov %0, %%cr0" ::"r"(cr0));
}

static page_table_t *get_page_table(address_space_t *space, uint32_t virtual,
                                    bool create) {
  uint32_t dir_index = PAGE_DIR_INDEX(virtual);
  uint32_t dir_entry = (*space->directory)[dir_index];

  if (!(dir_entry & PAGE_PRESENT)) {
    if (!create)
      return NULL;

    uint32_t table_phys = pmm_alloc_page();
    if (!table_phys)
      return NULL;

    page_table_t *table = (page_table_t *)table_phys;
    memset(table, 0, sizeof(page_table_t));

    (*space->directory)[dir_index] =
        table_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    flush_tlb_single(virtual);

    return table;
  }

  return (page_table_t *)(dir_entry & PAGE_FRAME(0xFFFFFFFF));
}

void paging_init(void) {
  printf("Initializing paging subsystem\n");

  uint32_t dir_phys = pmm_alloc_page();
  if (!dir_phys) {
    printf("FATAL: Cannot allocate page directory\n");
    return;
  }

  kernel_space.directory = (page_directory_t *)dir_phys;
  kernel_space.physical_addr = dir_phys;
  memset(kernel_space.directory, 0, sizeof(page_directory_t));

  uint32_t total_memory = pmm_get_total_memory();
  uint32_t identity_map_end = total_memory + PAGE_SIZE;

  printf("Identity mapping: 0x00000000 - 0x%08x (%d MB)\n", identity_map_end,
         identity_map_end / (1024 * 1024));
  paging_identity_map(&kernel_space, 0, identity_map_end,
                      PAGE_PRESENT | PAGE_WRITE);

  current_space = &kernel_space;
  enable_paging(kernel_space.physical_addr);

  printf("Paging enabled\n");
}

address_space_t *paging_create_address_space(void) {
  address_space_t *space = (address_space_t *)kmalloc(sizeof(address_space_t));
  if (!space)
    return NULL;

  uint32_t dir_phys = pmm_alloc_page();
  if (!dir_phys) {
    kfree(space);
    return NULL;
  }

  space->directory = (page_directory_t *)dir_phys;
  space->physical_addr = dir_phys;
  memset(space->directory, 0, sizeof(page_directory_t));

  for (int i = 768; i < TABLES_PER_DIR; i++) {
    (*space->directory)[i] = (*kernel_space.directory)[i];
  }

  return space;
}

void paging_destroy_address_space(address_space_t *space) {
  if (!space || space == &kernel_space)
    return;

  for (int i = 0; i < 768; i++) {
    uint32_t dir_entry = (*space->directory)[i];
    if (dir_entry & PAGE_PRESENT) {
      page_table_t *table =
          (page_table_t *)(dir_entry & PAGE_FRAME(0xFFFFFFFF));

      for (int j = 0; j < PAGES_PER_TABLE; j++) {
        uint32_t page_entry = (*table)[j];
        if (page_entry & PAGE_PRESENT) {
          pmm_free_page(page_entry & PAGE_FRAME(0xFFFFFFFF));
        }
      }

      pmm_free_page((uint32_t)table);
    }
  }

  pmm_free_page(space->physical_addr);
  kfree(space);
}

void paging_switch_directory(address_space_t *space) {
  if (!space)
    return;
  current_space = space;
  asm volatile("mov %0, %%cr3" ::"r"(space->physical_addr) : "memory");
}

address_space_t *paging_get_kernel_space(void) { return &kernel_space; }

bool paging_map_page(address_space_t *space, uint32_t virtual,
                     uint32_t physical, uint32_t flags) {
  if (!space)
    return false;

  page_table_t *table = get_page_table(space, virtual, true);
  if (!table)
    return false;

  uint32_t table_index = PAGE_TABLE_INDEX(virtual);
  (*table)[table_index] =
      (physical & PAGE_FRAME(0xFFFFFFFF)) | (flags & 0xFFF) | PAGE_PRESENT;

  if (space == current_space) {
    flush_tlb_single(virtual);
  }

  return true;
}

bool paging_unmap_page(address_space_t *space, uint32_t virtual) {
  if (!space)
    return false;

  page_table_t *table = get_page_table(space, virtual, false);
  if (!table)
    return false;

  uint32_t table_index = PAGE_TABLE_INDEX(virtual);
  (*table)[table_index] = 0;

  if (space == current_space) {
    flush_tlb_single(virtual);
  }

  return true;
}

uint32_t paging_get_physical(address_space_t *space, uint32_t virtual) {
  if (!space)
    return 0;

  page_table_t *table = get_page_table(space, virtual, false);
  if (!table)
    return 0;

  uint32_t table_index = PAGE_TABLE_INDEX(virtual);
  uint32_t page_entry = (*table)[table_index];

  if (!(page_entry & PAGE_PRESENT))
    return 0;

  return (page_entry & PAGE_FRAME(0xFFFFFFFF)) | (virtual & 0xFFF);
}

bool paging_is_mapped(address_space_t *space, uint32_t virtual) {
  return paging_get_physical(space, virtual) != 0;
}

void paging_map_range(address_space_t *space, uint32_t virt_start,
                      uint32_t phys_start, uint32_t size, uint32_t flags) {
  uint32_t virt = PAGE_FRAME(virt_start);
  uint32_t phys = PAGE_FRAME(phys_start);
  uint32_t end = PAGE_FRAME(virt_start + size + 0xFFF);

  while (virt < end) {
    paging_map_page(space, virt, phys, flags);
    virt += PAGE_SIZE;
    phys += PAGE_SIZE;
  }
}

void paging_identity_map(address_space_t *space, uint32_t start, uint32_t size,
                         uint32_t flags) {
  paging_map_range(space, start, start, size, flags);
}

void page_fault_handler(uint32_t error_code, uint32_t faulting_addr) {
  printf("\n=== PAGE FAULT ===\n");
  printf("Faulting address: 0x%08x\n", faulting_addr);
  printf("Error code: 0x%x ", error_code);

  if (!(error_code & 0x1))
    printf("[Page not present] ");
  if (error_code & 0x2)
    printf("[Write] ");
  else
    printf("[Read] ");
  if (error_code & 0x4)
    printf("[User mode] ");
  else
    printf("[Kernel mode] ");
  if (error_code & 0x8)
    printf("[Reserved bit] ");
  if (error_code & 0x10)
    printf("[Instruction fetch] ");

  printf("\n");

  for (;;) {
    asm volatile("cli; hlt");
  }
}
