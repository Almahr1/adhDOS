#include <kernel/gdt.h>
#include <stddef.h>
#include <stdint.h>

static struct gdt_entry gdt_entries[6];
static struct gdt_ptr gdt_pointer;
static struct tss_entry tss;

extern void gdt_flush(uint32_t);
extern void tss_flush(void);

static void gdt_set_gate(int32_t num, uint32_t base, uint32_t limit,
                         uint8_t access, uint8_t gran) {
  gdt_entries[num].base_low = (base & 0xFFFF);
  gdt_entries[num].base_middle = (base >> 16) & 0xFF;
  gdt_entries[num].base_high = (base >> 24) & 0xFF;

  gdt_entries[num].limit_low = (limit & 0xFFFF);

  // Pack the upper 4 bits of limit and the granularity flags into one byte
  gdt_entries[num].granularity = (limit >> 16) & 0x0F;
  gdt_entries[num].granularity |= gran & 0xF0;

  gdt_entries[num].access = access;
}

static void tss_init(void) {
  uint32_t base = (uint32_t)&tss;
  uint32_t limit = sizeof(tss) - 1;

  gdt_set_gate(5, base, limit, 0x89, 0x00);

  __builtin_memset(&tss, 0, sizeof(tss));
  tss.ss0 = KERNEL_DATA_SEGMENT;
  tss.iomap_base = sizeof(tss);

  tss_flush();
}

void tss_set_kernel_stack(uint32_t esp) {
  tss.esp0 = esp;
}

void gdt_init(void) {
  gdt_pointer.limit = (sizeof(struct gdt_entry) * 6) - 1;
  gdt_pointer.base = (uint32_t)&gdt_entries;

  uint8_t granularity = GDT_GRAN_4K | GDT_GRAN_32BIT;

  gdt_set_gate(0, 0, 0, 0, 0);
  gdt_set_gate(1, 0, 0xFFFFFFFF, GDT_CODE_PL0, granularity);
  gdt_set_gate(2, 0, 0xFFFFFFFF, GDT_DATA_PL0, granularity);
  gdt_set_gate(3, 0, 0xFFFFFFFF, GDT_CODE_PL3, granularity);
  gdt_set_gate(4, 0, 0xFFFFFFFF, GDT_DATA_PL3, granularity);

  gdt_flush((uint32_t)&gdt_pointer);
  tss_init();
}
