#ifndef PAGING_H
#define PAGING_H

#include <stdint.h>
#include <stdbool.h>

#define PAGE_PRESENT    0x001
#define PAGE_WRITE      0x002
#define PAGE_USER       0x004
#define PAGE_ACCESSED   0x020
#define PAGE_DIRTY      0x040
#define PAGE_SIZE_4MB   0x080
#define PAGE_GLOBAL     0x100

#define PAGES_PER_TABLE 1024
#define TABLES_PER_DIR  1024

#define PAGE_DIR_INDEX(addr)   (((addr) >> 22) & 0x3FF)
#define PAGE_TABLE_INDEX(addr) (((addr) >> 12) & 0x3FF)
#define PAGE_FRAME(addr)       ((addr) & 0xFFFFF000)

typedef uint32_t page_directory_t[TABLES_PER_DIR] __attribute__((aligned(4096)));
typedef uint32_t page_table_t[PAGES_PER_TABLE] __attribute__((aligned(4096)));

typedef struct {
    page_directory_t *directory;
    uint32_t physical_addr;
} address_space_t;

void paging_init(void);
address_space_t *paging_create_address_space(void);
void paging_destroy_address_space(address_space_t *space);
void paging_switch_directory(address_space_t *space);
address_space_t *paging_get_kernel_space(void);

bool paging_map_page(address_space_t *space, uint32_t virtual, uint32_t physical, uint32_t flags);
bool paging_unmap_page(address_space_t *space, uint32_t virtual);
uint32_t paging_get_physical(address_space_t *space, uint32_t virtual);
bool paging_is_mapped(address_space_t *space, uint32_t virtual);

void paging_map_range(address_space_t *space, uint32_t virt_start, uint32_t phys_start, uint32_t size, uint32_t flags);
void paging_identity_map(address_space_t *space, uint32_t start, uint32_t size, uint32_t flags);

void page_fault_handler(uint32_t error_code, uint32_t faulting_addr);

#endif
