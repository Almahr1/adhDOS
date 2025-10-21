#include <kernel/gdt.h>
#include <stddef.h>
#include <stdint.h>

static struct gdt_entry gdt_entries[5];
static struct gdt_ptr gdt_pointer;

extern void gdt_flush(uint32_t);

static void gdt_set_gate(int32_t num, uint32_t base, uint32_t limit,
                         uint8_t access, uint8_t gran) {
  gdt_entries[num].base_low = (base & 0xFFFF);
  gdt_entries[num].base_middle = (base >> 16) & 0xFF;
  gdt_entries[num].base_high = (base >> 24) & 0xFF;

  gdt_entries[num].limit_low = (limit & 0xFFFF);

  // Pack the upper 4 bits of limit and the granularity flags into one byte.
  gdt_entries[num].granularity = (limit >> 16) & 0x0F;
  gdt_entries[num].granularity |= gran & 0xF0;

  gdt_entries[num].access = access;
}

void gdt_init(void) {
  gdt_pointer.limit = (sizeof(struct gdt_entry) * 5) - 1;
  gdt_pointer.base = (uint32_t)&gdt_entries;

  uint8_t granularity = GDT_GRAN_4K | GDT_GRAN_32BIT;

  gdt_set_gate(0, 0, 0, 0, 0); // Null Segment
  gdt_set_gate(1, 0, 0xFFFFFFFF, GDT_CODE_PL0,
               granularity); // Kernel Code Segment
  gdt_set_gate(2, 0, 0xFFFFFFFF, GDT_DATA_PL0,
               granularity); // Kernel Data Segment
  gdt_set_gate(3, 0, 0xFFFFFFFF, GDT_CODE_PL3,
               granularity); // User Code Segment
  gdt_set_gate(4, 0, 0xFFFFFFFF, GDT_DATA_PL3,
               granularity); // User Data Segment

  gdt_flush((uint32_t)&gdt_pointer);
}
