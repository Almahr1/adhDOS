#include <kernel/pic.h>
#include <stdint.h>

// PIC ports
#define PIC1_COMMAND 0x20
#define PIC1_DATA 0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA 0xA1

// PIC initialization command words
#define ICW1_ICW4 0x01      // ICW4 needed
#define ICW1_SINGLE 0x02    // Single (cascade) mode
#define ICW1_INTERVAL4 0x04 // Call address interval 4 (8)
#define ICW1_LEVEL 0x08     // Level triggered (edge) mode
#define ICW1_INIT 0x10      // Initialization

#define ICW4_8086 0x01       // 8086/88 (MCS-80/85) mode
#define ICW4_AUTO 0x02       // Auto (normal) EOI
#define ICW4_BUF_SLAVE 0x08  // Buffered mode/slave
#define ICW4_BUF_MASTER 0x0C // Buffered mode/master
#define ICW4_SFNM 0x10       // Special fully nested (not)

// Helper function for I/O wait
static inline void io_wait(void) {
  // Port 0x80 is used for 'checkpoints' during POST
  // Writing to it causes a brief delay
  asm volatile("outb %%al, $0x80" : : "a"(0));
}

// Remap the PIC to avoid conflicts with CPU exceptions
void pic_remap(uint8_t offset1, uint8_t offset2) {
  uint8_t mask1, mask2;

  // Save current interrupt masks
  asm volatile("inb %1, %0" : "=a"(mask1) : "Nd"((uint16_t)PIC1_DATA));
  asm volatile("inb %1, %0" : "=a"(mask2) : "Nd"((uint16_t)PIC2_DATA));

  // Start initialization sequence in cascade mode
  asm volatile("outb %0, %1"
               :
               : "a"((uint8_t)(ICW1_INIT | ICW1_ICW4)),
                 "Nd"((uint16_t)PIC1_COMMAND));
  io_wait();
  asm volatile("outb %0, %1"
               :
               : "a"((uint8_t)(ICW1_INIT | ICW1_ICW4)),
                 "Nd"((uint16_t)PIC2_COMMAND));
  io_wait();

  // Set vector offsets (ICW2)
  asm volatile("outb %0, %1" : : "a"(offset1), "Nd"((uint16_t)PIC1_DATA));
  io_wait();
  asm volatile("outb %0, %1" : : "a"(offset2), "Nd"((uint16_t)PIC2_DATA));
  io_wait();

  // Tell master PIC there's a slave PIC at IRQ2 (ICW3)
  asm volatile("outb %0, %1" : : "a"((uint8_t)0x04), "Nd"((uint16_t)PIC1_DATA));
  io_wait();
  // Tell slave PIC its cascade identity (ICW3)
  asm volatile("outb %0, %1" : : "a"((uint8_t)0x02), "Nd"((uint16_t)PIC2_DATA));
  io_wait();

  // Set 8086 mode (ICW4)
  asm volatile("outb %0, %1"
               :
               : "a"((uint8_t)ICW4_8086), "Nd"((uint16_t)PIC1_DATA));
  io_wait();
  asm volatile("outb %0, %1"
               :
               : "a"((uint8_t)ICW4_8086), "Nd"((uint16_t)PIC2_DATA));
  io_wait();

  // Restore saved masks
  asm volatile("outb %0, %1" : : "a"(mask1), "Nd"((uint16_t)PIC1_DATA));
  asm volatile("outb %0, %1" : : "a"(mask2), "Nd"((uint16_t)PIC2_DATA));
}

// Disable the PIC (useful when switching to APIC)
void pic_disable(void) {
  // Mask all interrupts on both PICs
  asm volatile("outb %0, %1" : : "a"((uint8_t)0xFF), "Nd"((uint16_t)PIC1_DATA));
  asm volatile("outb %0, %1" : : "a"((uint8_t)0xFF), "Nd"((uint16_t)PIC2_DATA));
}

// Enable a specific IRQ line
void pic_enable_irq(uint8_t irq) {
  uint16_t port;
  uint8_t value;

  if (irq < 8) {
    port = PIC1_DATA;
  } else {
    port = PIC2_DATA;
    irq -= 8;
  }

  asm volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
  value &= ~(1 << irq);
  asm volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

// Disable a specific IRQ line
void pic_disable_irq(uint8_t irq) {
  uint16_t port;
  uint8_t value;

  if (irq < 8) {
    port = PIC1_DATA;
  } else {
    port = PIC2_DATA;
    irq -= 8;
  }

  asm volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
  value |= (1 << irq);
  asm volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

// Initialize PIC with standard remapping
void pic_init(void) {
  // Remap PIC to vectors 32-47 to avoid conflicts with CPU exceptions
  pic_remap(32, 40);
}
