#ifndef GDT_H
#define GDT_H

#ifndef __ASSEMBLER__
/* Only include these when compiling C code, not assembly */
#include <stdint.h>

struct gdt_entry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_middle;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
} __attribute__((packed));

struct gdt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

// Access byte flags
#define GDT_ACCESS_PRESENT       0x80  // Present bit
#define GDT_ACCESS_PRIV_RING0    0x00  // Ring 0 (kernel)
#define GDT_ACCESS_PRIV_RING3    0x60  // Ring 3 (user)
#define GDT_ACCESS_CODE_DATA     0x10  // Code/Data segment
#define GDT_ACCESS_EXECUTABLE    0x08  // Executable (code segment)
#define GDT_ACCESS_DIRECTION     0x04  // Direction/Conforming
#define GDT_ACCESS_RW            0x02  // Readable (code) / Writable (data)
#define GDT_ACCESS_ACCESSED      0x01

// Granularity flags
#define GDT_GRAN_4K              0x80  // 4KB granularity (1) vs 1B (0)
#define GDT_GRAN_32BIT           0x40  // 32-bit (1) vs 16-bit (0)
#define GDT_GRAN_64BIT           0x20  // 64-bit code segment
#define GDT_GRAN_AVL             0x10  // Available for system use

// Common access bytes
#define GDT_CODE_PL0  (GDT_ACCESS_PRESENT | GDT_ACCESS_PRIV_RING0 | \
                       GDT_ACCESS_CODE_DATA | GDT_ACCESS_EXECUTABLE | \
                       GDT_ACCESS_RW)

#define GDT_DATA_PL0  (GDT_ACCESS_PRESENT | GDT_ACCESS_PRIV_RING0 | \
                       GDT_ACCESS_CODE_DATA | GDT_ACCESS_RW)

#define GDT_CODE_PL3  (GDT_ACCESS_PRESENT | GDT_ACCESS_PRIV_RING3 | \
                       GDT_ACCESS_CODE_DATA | GDT_ACCESS_EXECUTABLE | \
                       GDT_ACCESS_RW)

#define GDT_DATA_PL3  (GDT_ACCESS_PRESENT | GDT_ACCESS_PRIV_RING3 | \
                       GDT_ACCESS_CODE_DATA | GDT_ACCESS_RW)

void gdt_init(void);

#endif /* __ASSEMBLER__ */

/* These segment selector definitions can be used in both C and assembly */
#define KERNEL_CODE_SEGMENT 0x08
#define KERNEL_DATA_SEGMENT 0x10
#define USER_CODE_SEGMENT   0x18
#define USER_DATA_SEGMENT   0x20

#endif /* GDT_H */
