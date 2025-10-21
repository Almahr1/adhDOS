#ifndef PIC_H
#define PIC_H

#include <stdint.h>

// Remap the PIC to specified vector offsets
void pic_remap(uint8_t offset1, uint8_t offset2);

// Initialize PIC with standard remapping (32-47)
void pic_init(void);

// Disable the PIC entirely
void pic_disable(void);

// Enable a specific IRQ line (0-15)
void pic_enable_irq(uint8_t irq);

// Disable a specific IRQ line (0-15)
void pic_disable_irq(uint8_t irq);

#endif // PIC_H
