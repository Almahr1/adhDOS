#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/multiboot.h>

#define PAGE_SIZE 4096
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_DOWN(addr) ((addr) & ~(PAGE_SIZE - 1))

#define MAX_ORDER 10
#define MIN_BLOCK_SIZE PAGE_SIZE

#define MEMORY_DEBUG 1
#define MAGIC_ALLOC 0xDEADBEEF
#define MAGIC_FREE  0xFEEDFACE
#define POISON_BYTE 0xAA

typedef struct free_block {
    struct free_block *next;
    struct free_block *prev;
} free_block_t;

typedef struct memory_region {
    uint32_t start;
    uint32_t end;
    uint32_t type;
    struct memory_region *next;
} memory_region_t;

typedef struct slab {
    void *free_list;
    uint16_t free_count;
    uint16_t total_count;
    uint32_t magic;
    struct slab *next;
    struct slab *prev;
} slab_t;

typedef struct cache {
    size_t object_size;
    size_t objects_per_slab;
    slab_t *partial_slabs;
    slab_t *full_slabs;
    slab_t *empty_slabs;
    uint32_t total_slabs;
    uint32_t total_objects;
    uint32_t allocated_objects;
    char name[32];
} cache_t;

typedef struct alloc_header {
    uint32_t magic;
    size_t size;
    cache_t *cache;
    struct alloc_header *next;
    struct alloc_header *prev;
} alloc_header_t;

void memory_init(multiboot_info_t *mboot_info);

uint32_t pmm_alloc_page(void);
uint32_t pmm_alloc_pages(uint8_t order);
void pmm_free_page(uint32_t page_addr);
void pmm_free_pages(uint32_t page_addr, uint8_t order);
uint32_t pmm_get_total_memory(void);
uint32_t pmm_get_free_memory(void);

void slab_init(void);
cache_t *cache_create(const char *name, size_t object_size);
void *cache_alloc(cache_t *cache);
void cache_free(cache_t *cache, void *ptr);
void cache_destroy(cache_t *cache);

void *kmalloc(size_t size);
void *kcalloc(size_t count, size_t size);
void *krealloc(void *ptr, size_t size);
void kfree(void *ptr);

void memory_print_stats(void);
void memory_print_caches(void);
void memory_print_leaks(void);
bool memory_run_tests(void);

uint8_t get_order(size_t size);
uint32_t get_buddy_addr(uint32_t addr, uint8_t order);
bool is_block_free(uint32_t addr, uint8_t order);
void set_block_allocated(uint32_t addr, uint8_t order);
void set_block_free(uint32_t addr, uint8_t order);

#endif