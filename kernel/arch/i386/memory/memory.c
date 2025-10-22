#include <kernel/memory.h>
#include <kernel/multiboot.h>
#include <stdio.h>
#include <string.h>

static free_block_t *free_lists[MAX_ORDER + 1];
static uint8_t *allocation_bitmaps[MAX_ORDER + 1];
static uint32_t bitmap_sizes[MAX_ORDER + 1];
static uint32_t memory_start;
static uint32_t memory_end;
static uint32_t total_pages;

extern uint32_t kernel_end;

uint8_t get_order(size_t size) {
    if (size <= MIN_BLOCK_SIZE) return 0;

    uint8_t order = 0;
    size_t block_size = MIN_BLOCK_SIZE;

    while (block_size < size && order <= MAX_ORDER) {
        block_size <<= 1;
        order++;
    }

    return (order <= MAX_ORDER) ? order : MAX_ORDER;
}

static bool is_address_aligned(uint32_t addr, uint8_t order) {
    uint32_t block_size = MIN_BLOCK_SIZE << order;
    return (addr & (block_size - 1)) == 0;
}

uint32_t get_buddy_addr(uint32_t addr, uint8_t order) {
    uint32_t block_size = MIN_BLOCK_SIZE << order;
    uint32_t relative_addr = addr - memory_start;
    return memory_start + (relative_addr ^ block_size);
}

static uint32_t get_bitmap_index(uint32_t addr, uint8_t order) {
    uint32_t relative_addr = addr - memory_start;
    uint32_t block_size = MIN_BLOCK_SIZE << order;
    return relative_addr / block_size;
}

bool is_block_free(uint32_t addr, uint8_t order) {
    if (order > MAX_ORDER) return false;

    uint32_t index = get_bitmap_index(addr, order);
    uint32_t byte_index = index / 8;
  uint32_t bit_index = index % 8;

  if (byte_index >= bitmap_sizes[order]) return false;

  return !(allocation_bitmaps[order][byte_index] & (1 << bit_index));
}

void set_block_allocated(uint32_t addr, uint8_t order) {
  if (order > MAX_ORDER) return;

  uint32_t index = get_bitmap_index(addr, order);
  uint32_t byte_index = index / 8;
  uint32_t bit_index = index % 8;

  if (byte_index < bitmap_sizes[order]) {
    allocation_bitmaps[order][byte_index] |= (1 << bit_index);
  }
}

void set_block_free(uint32_t addr, uint8_t order) {
  if (order > MAX_ORDER) return;

  uint32_t index = get_bitmap_index(addr, order);
  uint32_t byte_index = index / 8;
  uint32_t bit_index = index % 8;

  if (byte_index < bitmap_sizes[order]) {
    allocation_bitmaps[order][byte_index] &= ~(1 << bit_index);
  }
}

static void remove_from_free_list(free_block_t *block, uint8_t order) {
  if (block->prev) {
    block->prev->next = block->next;
  } else {
    free_lists[order] = block->next;
  }

  if (block->next) {
    block->next->prev = block->prev;
  }
}

static void add_to_free_list(uint32_t addr, uint8_t order) {
  free_block_t *block = (free_block_t*)addr;
  block->next = free_lists[order];
  block->prev = NULL;

  if (free_lists[order]) {
    free_lists[order]->prev = block;
  }

  free_lists[order] = block;
}

uint32_t pmm_alloc_pages(uint8_t order) {
  if (order > MAX_ORDER) return 0;

  for (uint8_t current_order = order; current_order <= MAX_ORDER; current_order++) {
    if (free_lists[current_order]) {
      free_block_t *block = free_lists[current_order];
      uint32_t addr = (uint32_t)block;

      remove_from_free_list(block, current_order);
      set_block_allocated(addr, current_order);

      while (current_order > order) {
        current_order--;
        uint32_t buddy_addr = get_buddy_addr(addr, current_order);
        set_block_free(buddy_addr, current_order);
        add_to_free_list(buddy_addr, current_order);
      }

      set_block_allocated(addr, order);
      return addr;
    }
  }

  return 0;
}

void pmm_free_pages(uint32_t addr, uint8_t order) {
  if (addr < memory_start || addr >= memory_end) return;
  if (order > MAX_ORDER) return;
  if (!is_address_aligned(addr, order)) {
    printf("ERROR: Unaligned free addr=0x%x order=%d\n", addr, order);
    return;
  }

  // Coalesce with buddy blocks
  while (order < MAX_ORDER) {
    uint32_t buddy_addr = get_buddy_addr(addr, order);

    // Check bounds
    if (buddy_addr < memory_start || buddy_addr >= memory_end) {
      break;
    }

    // Check if buddy is free in bitmap
    if (!is_block_free(buddy_addr, order)) {
      break;
    }

    // Remove buddy from free list (it should be there if bitmap says it's free)
    free_block_t *buddy_block = (free_block_t*)buddy_addr;
    remove_from_free_list(buddy_block, order);

    // Mark both blocks as allocated in current order
    set_block_allocated(addr, order);
    set_block_allocated(buddy_addr, order);

    // Coalesce into larger block
    if (addr > buddy_addr) {
      addr = buddy_addr;
    }

    order++;
  }

  // Mark the final coalesced block as free and add to free list
  set_block_free(addr, order);
  add_to_free_list(addr, order);
}

uint32_t pmm_alloc_page(void) {
  return pmm_alloc_pages(0);
}

void pmm_free_page(uint32_t page_addr) {
  pmm_free_pages(page_addr, 0);
}

static void pmm_init_region(uint32_t start, uint32_t length) {
  start = PAGE_ALIGN(start);
  length = PAGE_ALIGN_DOWN(length);

  printf("Initializing memory region: 0x%x - 0x%x (%d MB)\n", 
         start, start + length, length / (1024 * 1024));

  for (uint32_t addr = start; addr < start + length; addr += MIN_BLOCK_SIZE) {
    if (addr >= memory_start && addr < memory_end) {
      pmm_free_pages(addr, 0);
    }
  }
}

void memory_init(multiboot_info_t *mboot_info) {
  printf("Buddy System Memory Manager initialization\n");

  if (!(mboot_info->flags & MULTIBOOT_FLAG_MEM)) {
    printf("ERROR: No basic memory info available!\n");
    return;
  }

  printf("Lower memory: %dKB\n", mboot_info->mem_lower);
  printf("Upper memory: %dKB\n", mboot_info->mem_upper);

  uint32_t kernel_end_addr = (uint32_t)&kernel_end;
  memory_start = PAGE_ALIGN(kernel_end_addr);
  memory_end = 0x1000000 + (mboot_info->mem_upper * 1024);

  total_pages = (memory_end - memory_start) / PAGE_SIZE;
    
  // Calculate bitmap sizes for each order and allocate them
  uint32_t total_bitmap_size = 0;
  for (uint8_t order = 0; order <= MAX_ORDER; order++) {
    uint32_t blocks_at_order = total_pages >> order; // Divide by 2^order
    bitmap_sizes[order] = (blocks_at_order + 7) / 8;  // Bits to bytes
    total_bitmap_size += PAGE_ALIGN(bitmap_sizes[order]);
  }

  printf("Total bitmap size needed: %d bytes\n", total_bitmap_size);

  // Allocate space for all bitmaps
  uint8_t *bitmap_start = (uint8_t*)memory_start;
  memory_start += total_bitmap_size;

  // Set up individual bitmap pointers
  uint32_t bitmap_offset = 0;
  for (uint8_t order = 0; order <= MAX_ORDER; order++) {
    allocation_bitmaps[order] = bitmap_start + bitmap_offset;
    bitmap_offset += PAGE_ALIGN(bitmap_sizes[order]);

    // Initialize all blocks as allocated (we'll free them later)
    memset(allocation_bitmaps[order], 0xFF, bitmap_sizes[order]);

    printf("Order %d: %d blocks, bitmap size %d bytes at %p\n", 
           order, total_pages >> order, bitmap_sizes[order], allocation_bitmaps[order]);
  }

  for (int i = 0; i <= MAX_ORDER; i++) {
    free_lists[i] = NULL;
  }

  printf("Memory range: 0x%x - 0x%x\n", memory_start, memory_end);
  printf("Total bitmap size: %d bytes\n", total_bitmap_size);
    
  if (!(mboot_info->flags & MULTIBOOT_FLAG_MMAP)) {
    printf("No memory map, using basic info\n");
    if (memory_end > memory_start) {
      pmm_init_region(memory_start, memory_end - memory_start);
    }
    return;
  }

  multiboot_mmap_entry_t *mmap = (multiboot_mmap_entry_t*)mboot_info->mmap_addr;
  multiboot_mmap_entry_t *mmap_end_ptr = (multiboot_mmap_entry_t*)
      (mboot_info->mmap_addr + mboot_info->mmap_length);

  printf("Memory Map:\n");
  while (mmap < mmap_end_ptr) {
    printf("  0x%08x-0x%08x: %s\n",
           (uint32_t)mmap->addr,
           (uint32_t)(mmap->addr + mmap->len - 1),
           (mmap->type == MULTIBOOT_MEMORY_AVAILABLE) ? "Available" : "Reserved");

    if (mmap->type == MULTIBOOT_MEMORY_AVAILABLE && mmap->addr >= 0x100000) {
      uint32_t region_start = (uint32_t)mmap->addr;
      uint32_t region_length = (uint32_t)mmap->len;

      if (region_start < memory_start) {
        if (region_start + region_length > memory_start) {
          region_length -= (memory_start - region_start);
          region_start = memory_start;
        } else {
          region_length = 0;
        }
      }

      if (region_start + region_length > memory_end) {
        region_length = memory_end - region_start;
      }

      if (region_length > 0) {
        pmm_init_region(region_start, region_length);
      }
    }

    mmap = (multiboot_mmap_entry_t*)((uint32_t)mmap + mmap->size + sizeof(mmap->size));
  }

  // Initialize slab allocator
  slab_init();
}

uint32_t pmm_get_total_memory(void) {
  return total_pages * PAGE_SIZE;
}

uint32_t pmm_get_free_memory(void) {
  uint32_t free_pages = 0;

  for (uint8_t order = 0; order <= MAX_ORDER; order++) {
    free_block_t *block = free_lists[order];
    uint32_t pages_per_block = 1 << order;

    while (block) {
      free_pages += pages_per_block;
      block = block->next;
    }
  }

  return free_pages * PAGE_SIZE;
}

// Slab allocator implementation
static cache_t *caches[16];
static int cache_count = 0;
static alloc_header_t *allocation_list = NULL;

// Standard cache sizes (removed 4096 since objects this large can't fit in page with slab header)
static size_t cache_sizes[] = {8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 0};

void slab_init(void) {
  cache_count = 0;
  allocation_list = NULL;

  // Create standard caches
  for (int i = 0; cache_sizes[i] != 0; i++) {
    char name[32];
    size_t size = cache_sizes[i];

    strcpy(name, "kmalloc-");

    // Generate proper cache names based on size
    if (size < 10) {
      name[8] = '0' + (char)size;
      name[9] = '\0';
    } else if (size < 100) {
      name[8] = '0' + (char)(size / 10);
      name[9] = '0' + (char)(size % 10);
      name[10] = '\0';
    } else if (size < 1000) {
      name[8] = '0' + (char)(size / 100);
      name[9] = '0' + (char)((size / 10) % 10);
      name[10] = '0' + (char)(size % 10);
      name[11] = '\0';
    } else {
      // For sizes >= 1000, use size in KB with 'k' suffix
      size_t kb = size / 1024;
      name[8] = '0' + (char)kb;
      name[9] = 'k';
      name[10] = '\0';
    }

    caches[cache_count] = cache_create(name, cache_sizes[i]);
    if (caches[cache_count]) {
      cache_count++;
    }
  }

  printf("Slab allocator initialized with %d caches\n", cache_count);
}

cache_t *cache_create(const char *name, size_t object_size) {
  // Reject zero-sized objects
  if (object_size == 0) return NULL;

  // Ensure there's room for at least one object plus slab header
  // Use effective object size (minimum sizeof(void*) for free list pointers)
  size_t effective_object_size = object_size < sizeof(void*) ? sizeof(void*) : object_size;
  if (sizeof(slab_t) + effective_object_size > PAGE_SIZE) return NULL;

  cache_t *cache = (cache_t*)pmm_alloc_page();
  if (!cache) return NULL;

  memset(cache, 0, sizeof(cache_t));
  cache->object_size = object_size;
  // Calculate objects per slab using effective object size
  cache->objects_per_slab = (PAGE_SIZE - sizeof(slab_t)) / effective_object_size;
  strncpy(cache->name, name, sizeof(cache->name) - 1);

  printf("Created cache '%s' - object_size=%d, objects_per_slab=%d\n", 
         name, (int)object_size, (int)cache->objects_per_slab);

  return cache;
}

static slab_t *slab_create(cache_t *cache) {
  uint32_t page = pmm_alloc_page();
  if (!page) return NULL;

  slab_t *slab = (slab_t*)page;
  slab->magic = MAGIC_ALLOC;
  slab->total_count = cache->objects_per_slab;
  slab->free_count = cache->objects_per_slab;
  slab->next = NULL;
  slab->prev = NULL;

  // Set up free list within the slab
  char *obj_start = (char*)slab + sizeof(slab_t);
  slab->free_list = obj_start;

  // Chain all objects together using effective object size for spacing
  size_t effective_object_size = cache->object_size < sizeof(void*) ? sizeof(void*) : cache->object_size;
  for (size_t i = 0; i < cache->objects_per_slab - 1; i++) {
    void **current = (void**)(obj_start + i * effective_object_size);
    *current = obj_start + (i + 1) * effective_object_size;
  }
  // Last object points to NULL
  void **last = (void**)(obj_start + (cache->objects_per_slab - 1) * effective_object_size);
  *last = NULL;

  cache->total_slabs++;
  cache->total_objects += cache->objects_per_slab;

  return slab;
}

void *cache_alloc(cache_t *cache) {
  if (!cache) return NULL;

  slab_t *slab = cache->partial_slabs;

  // No partial slabs, try to get from empty slabs
  if (!slab) {
    slab = cache->empty_slabs;
    if (slab) {
      // Move from empty to partial
      if (slab->next) slab->next->prev = slab->prev;
      if (slab->prev) slab->prev->next = slab->next;
      else cache->empty_slabs = slab->next;

      slab->next = cache->partial_slabs;
      slab->prev = NULL;
      if (cache->partial_slabs) cache->partial_slabs->prev = slab;
      cache->partial_slabs = slab;
    }
  }

  // Still no slab, create new one
  if (!slab) {
    slab = slab_create(cache);
    if (!slab) return NULL;

    slab->next = cache->partial_slabs;
    if (cache->partial_slabs) cache->partial_slabs->prev = slab;
    cache->partial_slabs = slab;
  }

  // Allocate object from slab
  void *obj = slab->free_list;
  if (!obj) return NULL;

  slab->free_list = *(void**)obj;
  slab->free_count--;
  cache->allocated_objects++;

  // If slab is now full, move to full list
  if (slab->free_count == 0) {
    // Remove from partial list
    if (slab->next) slab->next->prev = slab->prev;
    if (slab->prev) slab->prev->next = slab->next;
    else cache->partial_slabs = slab->next;

    // Add to full list
    slab->next = cache->full_slabs;
    slab->prev = NULL;
    if (cache->full_slabs) cache->full_slabs->prev = slab;
    cache->full_slabs = slab;
  }

  #if MEMORY_DEBUG
  memset(obj, POISON_BYTE, cache->object_size);
  #endif

  return obj;
}

void cache_free(cache_t *cache, void *ptr) {
  if (!cache || !ptr) return;

  // Find which slab contains this pointer
  uint32_t page_addr = (uint32_t)ptr & ~(PAGE_SIZE - 1);
  slab_t *slab = (slab_t*)page_addr;

  if (slab->magic != MAGIC_ALLOC) {
    printf("ERROR: Invalid slab magic 0x%x in cache_free! ptr=%p\n", slab->magic, ptr);
    return;
  }

  // Validate pointer is within slab bounds
  char *slab_start = (char*)slab + sizeof(slab_t);
  size_t effective_object_size = cache->object_size < sizeof(void*) ? sizeof(void*) : cache->object_size;
  char *slab_end = slab_start + (cache->objects_per_slab * effective_object_size);

  if ((char*)ptr < slab_start || (char*)ptr >= slab_end) {
    printf("ERROR: Pointer %p out of slab bounds [%p, %p) for cache '%s'\n", 
           ptr, slab_start, slab_end, cache->name);
    return;
  }

  // Validate pointer alignment
  uint32_t offset = (char*)ptr - slab_start;
  if (offset % effective_object_size != 0) {
    printf("ERROR: Misaligned pointer %p in cache '%s' (offset=%d, obj_size=%zu)\n",
           ptr, cache->name, offset, effective_object_size);
    return;
  }

  bool was_full = (slab->free_count == 0);

  // Add object back to free list
  *(void**)ptr = slab->free_list;
  slab->free_list = ptr;
  slab->free_count++;
  cache->allocated_objects--;

  #if MEMORY_DEBUG
  if (cache->object_size > sizeof(void*)) {
    memset((char*)ptr + sizeof(void*), POISON_BYTE, cache->object_size - sizeof(void*));
  }
  #endif

  // If slab was full, move to partial list
  if (was_full) {
    // Remove from full list
    if (slab->next) slab->next->prev = slab->prev;
    if (slab->prev) slab->prev->next = slab->next;
    else cache->full_slabs = slab->next;

    // Add to partial list
    slab->next = cache->partial_slabs;
    slab->prev = NULL;
    if (cache->partial_slabs) cache->partial_slabs->prev = slab;
    cache->partial_slabs = slab;
  }

  // If slab is now empty, move to empty list
  if (slab->free_count == cache->objects_per_slab) {
    // Remove from partial list
    if (slab->next) slab->next->prev = slab->prev;
    if (slab->prev) slab->prev->next = slab->next;
    else cache->partial_slabs = slab->next;

    // Add to empty list
    slab->next = cache->empty_slabs;
    slab->prev = NULL;
    if (cache->empty_slabs) cache->empty_slabs->prev = slab;
    cache->empty_slabs = slab;
  }
}

static cache_t *find_cache(size_t size) {
  for (int i = 0; i < cache_count; i++) {
    if (caches[i] && caches[i]->object_size >= size) {
      return caches[i];
    }
  }
  return NULL;
}

void *kmalloc(size_t size) {
  if (size == 0) return NULL;

  #if MEMORY_DEBUG
  size_t total_size = size + sizeof(alloc_header_t);
  #else
  size_t total_size = size;
  #endif

  void *ptr;
  cache_t *cache = NULL;

  // Try slab allocator for small objects (up to our largest cache size)
  if (total_size <= 2048) {
    cache = find_cache(total_size);
    if (cache) {
      ptr = cache_alloc(cache);
    } else {
      // No suitable cache found, use buddy allocator
      uint8_t order = get_order(total_size);
      uint32_t addr = pmm_alloc_pages(order);
      ptr = (addr != 0) ? (void*)addr : NULL;
    }
  } else {
    // Use buddy allocator for large objects (> 2048 bytes)
    uint8_t order = get_order(total_size);
    uint32_t addr = pmm_alloc_pages(order);
    ptr = (addr != 0) ? (void*)addr : NULL;
  }

  #if MEMORY_DEBUG
  if (ptr) {
    alloc_header_t *header = (alloc_header_t*)ptr;
    header->magic = MAGIC_ALLOC;
    header->size = size;
    header->cache = cache;
    header->next = allocation_list;
    header->prev = NULL;

    if (allocation_list) {
      allocation_list->prev = header;
    }
    allocation_list = header;

    return (char*)ptr + sizeof(alloc_header_t);
  }
  #endif

  return ptr;
}

void *kcalloc(size_t count, size_t size) {
  size_t user_size = count * size;
  void *ptr = kmalloc(user_size);

  if (ptr) {
    memset(ptr, 0, user_size);
  }

  return ptr;
}

void *krealloc(void *ptr, size_t size) {
  if (!ptr) return kmalloc(size);
  if (size == 0) {
    kfree(ptr);
    return NULL;
  }

  #if MEMORY_DEBUG
  alloc_header_t *header = (alloc_header_t*)((char*)ptr - sizeof(alloc_header_t));
  if (header->magic != MAGIC_ALLOC) {
    printf("ERROR: Invalid magic in krealloc!\n");
    return NULL;
  }

  size_t old_size = header->size;
  #else
  size_t old_size = size; // Best guess without debug info
  #endif

  void *new_ptr = kmalloc(size);
  if (new_ptr && ptr) {
    memcpy(new_ptr, ptr, (old_size < size) ? old_size : size);
    kfree(ptr);
  }

  return new_ptr;
}

void kfree(void *ptr) {
  if (!ptr) return;

  #if MEMORY_DEBUG
  alloc_header_t *header = (alloc_header_t*)((char*)ptr - sizeof(alloc_header_t));

  if (header->magic != MAGIC_ALLOC) {
    printf("ERROR: Invalid magic in kfree! ptr=%p\n", ptr);
    return;
  }

  // Remove from allocation list
  if (header->next) header->next->prev = header->prev;
  if (header->prev) header->prev->next = header->next;
  else allocation_list = header->next;

  // Poison the allocation
  memset(ptr, POISON_BYTE, header->size);
  header->magic = MAGIC_FREE;

  if (header->cache) {
    cache_free(header->cache, header);
  } else {
    uint32_t addr = (uint32_t)header;
    uint8_t order = get_order(header->size + sizeof(alloc_header_t));
    pmm_free_pages(addr, order);
  }
  #else
  // Without debug info, assume it's from slab if aligned to page
  uint32_t addr = (uint32_t)ptr;
  if ((addr & (PAGE_SIZE - 1)) != 0) {
    // Likely from slab, but we don't know which cache
    printf("WARNING: Cannot free slab object without debug info\n");
  } else {
    pmm_free_pages(addr, 0);
  }
  #endif
}

void memory_print_stats(void) {
    printf("=== Memory Statistics ===\n");
    printf("Total memory: %d MB\n", pmm_get_total_memory() / (1024 * 1024));
    printf("Free memory: %d MB\n", pmm_get_free_memory() / (1024 * 1024));
    printf("Used memory: %d MB\n", 
           (pmm_get_total_memory() - pmm_get_free_memory()) / (1024 * 1024));
    
    printf("Buddy allocator free lists:\n");
    for (uint8_t order = 0; order <= MAX_ORDER; order++) {
        uint32_t count = 0;
        free_block_t *block = free_lists[order];
        
        while (block) {
            count++;
            block = block->next;
        }
        
        if (count > 0) {
            uint32_t block_size = MIN_BLOCK_SIZE << order;
            printf("  Order %d (%d KB): %d blocks\n", 
                   order, block_size / 1024, count);
        }
    }
}

void memory_print_caches(void) {
    printf("=== Slab Cache Statistics ===\n");
    for (int i = 0; i < cache_count; i++) {
        cache_t *cache = caches[i];
        if (!cache) continue;
        
        uint32_t partial_slabs = 0, full_slabs = 0, empty_slabs = 0;
        
        slab_t *slab = cache->partial_slabs;
        while (slab) { partial_slabs++; slab = slab->next; }
        
        slab = cache->full_slabs;
        while (slab) { full_slabs++; slab = slab->next; }
        
        slab = cache->empty_slabs;
        while (slab) { empty_slabs++; slab = slab->next; }
        
        printf("Cache '%s':\n", cache->name);
        printf("  Object size: %d bytes\n", (int)cache->object_size);
        printf("  Objects per slab: %d\n", (int)cache->objects_per_slab);
        printf("  Total slabs: %d (partial: %d, full: %d, empty: %d)\n",
               cache->total_slabs, partial_slabs, full_slabs, empty_slabs);
        printf("  Total objects: %d, allocated: %d\n",
               cache->total_objects, cache->allocated_objects);
        printf("  Efficiency: %d%%\n", 
               cache->total_objects > 0 ? 
               (cache->allocated_objects * 100) / cache->total_objects : 0);
    }
}

void memory_print_leaks(void) {
    printf("=== Memory Leak Detection ===\n");
    
    #if MEMORY_DEBUG
    uint32_t leak_count = 0;
    size_t leak_bytes = 0;
    
    alloc_header_t *header = allocation_list;
    while (header) {
        if (header->magic == MAGIC_ALLOC) {
            printf("LEAK: %zu bytes at %p from %s\n", 
                   header->size, 
                   (char*)header + sizeof(alloc_header_t),
                   header->cache ? header->cache->name : "buddy");
            leak_count++;
            leak_bytes += header->size;
        }
        header = header->next;
    }
    
    if (leak_count == 0) {
        printf("No memory leaks detected!\n");
    } else {
        printf("Found %d leaks totaling %zu bytes\n", leak_count, leak_bytes);
    }
    #else
    printf("Memory debugging disabled - cannot detect leaks\n");
    #endif
}

// Comprehensive memory allocator test suite
bool memory_run_tests(void) {
    printf("=== Memory Allocator Test Suite ===\n");
    bool all_passed = true;
    
    // Test 1: Basic allocation/deallocation
    printf("Test 1: Basic allocation/deallocation... ");
    void *ptr1 = kmalloc(64);
    void *ptr2 = kmalloc(128);
    void *ptr3 = kmalloc(256);
    
    if (!ptr1 || !ptr2 || !ptr3) {
        printf("FAIL - allocation returned NULL\n");
        all_passed = false;
    } else {
        kfree(ptr1);
        kfree(ptr2);
        kfree(ptr3);
        printf("PASS\n");
    }
    
    // Test 2: Size rounding
    printf("Test 2: Size rounding... ");
    void *ptr_small = kmalloc(1);   // Should use 8-byte cache
    void *ptr_odd = kmalloc(100);   // Should use 128-byte cache
    
    if (!ptr_small || !ptr_odd) {
        printf("FAIL - allocation returned NULL\n");
        all_passed = false;
    } else {
        kfree(ptr_small);
        kfree(ptr_odd);
        printf("PASS\n");
    }
    
    // Test 3: Large allocation (buddy allocator)
    printf("Test 3: Large allocation... ");
    void *large_ptr = kmalloc(8192);  // Should use buddy allocator
    
    if (!large_ptr) {
        printf("FAIL - large allocation returned NULL\n");
        all_passed = false;
    } else {
        kfree(large_ptr);
        printf("PASS\n");
    }
    
    // Test 4: Zero-sized allocation
    printf("Test 4: Zero-sized allocation... ");
    void *zero_ptr = kmalloc(0);
    
    if (zero_ptr != NULL) {
        printf("FAIL - kmalloc(0) should return NULL\n");
        all_passed = false;
    } else {
        printf("PASS\n");
    }
    
    // Test 5: kcalloc (zeroed memory)
    printf("Test 5: kcalloc (zeroed memory)... ");
    uint32_t *arr = (uint32_t*)kcalloc(10, sizeof(uint32_t));
    bool all_zero = true;
    
    if (!arr) {
        printf("FAIL - kcalloc returned NULL\n");
        all_passed = false;
    } else {
        for (int i = 0; i < 10; i++) {
            if (arr[i] != 0) {
                all_zero = false;
                break;
            }
        }
        
        if (!all_zero) {
            printf("FAIL - kcalloc didn't zero memory\n");
            all_passed = false;
        } else {
            printf("PASS\n");
        }
        kfree(arr);
    }
    
    // Test 6: krealloc
    printf("Test 6: krealloc... ");
    void *realloc_ptr = kmalloc(32);
    
    if (!realloc_ptr) {
        printf("FAIL - initial allocation failed\n");
        all_passed = false;
    } else {
        // Fill with pattern
        memset(realloc_ptr, 0x42, 32);
        
        // Expand
        realloc_ptr = krealloc(realloc_ptr, 64);
        
        if (!realloc_ptr) {
            printf("FAIL - krealloc returned NULL\n");
            all_passed = false;
        } else {
            // Check if data was preserved
            bool data_preserved = true;
            uint8_t *bytes = (uint8_t*)realloc_ptr;
            for (int i = 0; i < 32; i++) {
                if (bytes[i] != 0x42) {
                    data_preserved = false;
                    break;
                }
            }
            
            if (!data_preserved) {
                printf("FAIL - krealloc didn't preserve data\n");
                all_passed = false;
            } else {
                printf("PASS\n");
            }
            kfree(realloc_ptr);
        }
    }
    
    // Test 7: Stress test - many small allocations
    printf("Test 7: Stress test (1000 small allocations)... ");
    void *ptrs[1000];
    bool stress_passed = true;
    
    // Allocate
    for (int i = 0; i < 1000; i++) {
        ptrs[i] = kmalloc(32 + (i % 64));  // Varying sizes
        if (!ptrs[i]) {
            stress_passed = false;
            break;
        }
    }
    
    // Free in reverse order
    for (int i = 999; i >= 0; i--) {
        if (ptrs[i]) {
            kfree(ptrs[i]);
        }
    }
    
    if (!stress_passed) {
        printf("FAIL - stress test allocation failed\n");
        all_passed = false;
    } else {
        printf("PASS\n");
    }
    
    // Test 8: Fragment and coalesce test
    printf("Test 8: Fragmentation/coalescing... ");
    void *frag_ptrs[10];
    
    // Allocate 10 consecutive pages
    for (int i = 0; i < 10; i++) {
        frag_ptrs[i] = kmalloc(4096);
        if (!frag_ptrs[i]) {
            printf("FAIL - couldn't allocate pages for fragmentation test\n");
            all_passed = false;
            goto cleanup_frag;
        }
    }
    
    // Free every other page
    for (int i = 0; i < 10; i += 2) {
        kfree(frag_ptrs[i]);
        frag_ptrs[i] = NULL;
    }
    
    // Try to allocate a large block - should work due to coalescing
    void *large_block = kmalloc(8192);
    if (!large_block) {
        printf("FAIL - couldn't allocate large block (coalescing issue?)\n");
        all_passed = false;
    } else {
        kfree(large_block);
        printf("PASS\n");
    }
    
cleanup_frag:
    // Clean up remaining pointers
    for (int i = 0; i < 10; i++) {
        if (frag_ptrs[i]) {
            kfree(frag_ptrs[i]);
        }
    }
    
    // Test 9: Slab allocator - small size testing
    printf("Test 9: Slab allocator small sizes (8-96 bytes)... ");
    bool slab_test_passed = true;
    void *slab_ptrs[50];
    
    // Test various small sizes that should use slab allocator
    size_t test_sizes[] = {8, 16, 24, 32, 48, 64, 80, 96};
    size_t num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);
    
    for (size_t s = 0; s < num_sizes; s++) {
        size_t size = test_sizes[s];
        
        // Allocate multiple objects of each size
        for (int i = 0; i < 6; i++) {
            slab_ptrs[i] = kmalloc(size);
            if (!slab_ptrs[i]) {
                printf("FAIL - allocation of %zu bytes returned NULL\n", size);
                slab_test_passed = false;
                goto cleanup_slab;
            }
            
            // Write pattern to verify no corruption
            memset(slab_ptrs[i], 0x33 + i, size);
        }
        
        // Verify data integrity
        for (int i = 0; i < 6; i++) {
            uint8_t *bytes = (uint8_t*)slab_ptrs[i];
            for (size_t j = 0; j < size; j++) {
                if (bytes[j] != (uint8_t)(0x33 + i)) {
                    printf("FAIL - data corruption in %zu byte allocation\n", size);
                    slab_test_passed = false;
                    goto cleanup_slab;
                }
            }
        }
        
        // Free them
        for (int i = 0; i < 6; i++) {
            kfree(slab_ptrs[i]);
            slab_ptrs[i] = NULL;
        }
    }
    
    if (slab_test_passed) {
        printf("PASS\n");
    }
    
cleanup_slab:
    // Clean up any remaining slab test pointers
    for (int i = 0; i < 50; i++) {
        if (slab_ptrs[i]) {
            kfree(slab_ptrs[i]);
        }
    }
    
    // Test 10: Slab allocator object reuse
    printf("Test 10: Slab object reuse... ");
    bool reuse_test_passed = true;
    
    // Allocate and free the same size multiple times to test reuse
    void *first_ptr = kmalloc(32);
    void *second_ptr = kmalloc(32);
    void *third_ptr = kmalloc(32);
    
    if (!first_ptr || !second_ptr || !third_ptr) {
        printf("FAIL - initial allocations failed\n");
        reuse_test_passed = false;
    } else {
        kfree(second_ptr);  // Free middle one
        
        void *reuse_ptr = kmalloc(32);  // Should reuse the freed slot
        if (!reuse_ptr) {
            printf("FAIL - reuse allocation failed\n");
            reuse_test_passed = false;
        } else {
            // Test that we can write to reused memory
            memset(reuse_ptr, 0x55, 32);
            
            kfree(reuse_ptr);
            printf("PASS\n");
        }
        
        kfree(first_ptr);
        kfree(third_ptr);
    }
    
    if (!reuse_test_passed) {
        all_passed = false;
    }
    
    // Test 11: Cache efficiency test
    printf("Test 11: Cache efficiency test... ");
    bool efficiency_passed = true;
    void *cache_ptrs[100];
    
    // Allocate many small objects to fill up slabs
    for (int i = 0; i < 100; i++) {
        cache_ptrs[i] = kmalloc(16);  // Use 16-byte cache
        if (!cache_ptrs[i]) {
            printf("FAIL - allocation %d failed\n", i);
            efficiency_passed = false;
            break;
        }
        
        // Write unique pattern
        uint16_t *data = (uint16_t*)cache_ptrs[i];
        for (int j = 0; j < 8; j++) {
            data[j] = (uint16_t)(i * 8 + j);
        }
    }
    
    // Verify all data is intact
    if (efficiency_passed) {
        for (int i = 0; i < 100; i++) {
            uint16_t *data = (uint16_t*)cache_ptrs[i];
            for (int j = 0; j < 8; j++) {
                if (data[j] != (uint16_t)(i * 8 + j)) {
                    printf("FAIL - data corruption at allocation %d, offset %d\n", i, j);
                    efficiency_passed = false;
                    break;
                }
            }
            if (!efficiency_passed) break;
        }
    }
    
    // Free every other allocation to create fragmentation
    for (int i = 0; i < 100; i += 2) {
        kfree(cache_ptrs[i]);
        cache_ptrs[i] = NULL;
    }
    
    // Try to allocate more - should reuse freed slots
    for (int i = 0; i < 50 && efficiency_passed; i++) {
        void *new_ptr = kmalloc(16);
        if (!new_ptr) {
            printf("FAIL - reallocation %d failed\n", i);
            efficiency_passed = false;
        } else {
            kfree(new_ptr);
        }
    }
    
    // Clean up remaining allocations
    for (int i = 1; i < 100; i += 2) {
        if (cache_ptrs[i]) {
            kfree(cache_ptrs[i]);
        }
    }
    
    if (efficiency_passed) {
        printf("PASS\n");
    } else {
        all_passed = false;
    }
    
    printf("=== Test Results ===\n");
    printf("Overall result: %s\n", all_passed ? "ALL TESTS PASSED!" : "SOME TESTS FAILED!");
    
    return all_passed;
}