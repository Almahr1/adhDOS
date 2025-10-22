#include <kernel/serial.h>
#include <string.h>

#define SERIAL_DATA_REG(port) (port)
#define SERIAL_FIFO_CTRL_REG(port) ((port) + 2)
#define SERIAL_LINE_CTRL_REG(port) ((port) + 3)
#define SERIAL_MODEM_CTRL_REG(port) ((port) + 4)
#define SERIAL_LINE_STATUS_REG(port) ((port) + 5)
#define SERIAL_MODEM_STATUS_REG(port) ((port) + 6)
#define SERIAL_DIVISOR_LSB(port) (port)
#define SERIAL_DIVISOR_MSB(port) ((port) + 1)

#define SERIAL_LINE_DLAB 0x80
#define SERIAL_FIFO_ENABLE 0x01
#define SERIAL_FIFO_CLEAR_RX 0x02
#define SERIAL_FIFO_CLEAR_TX 0x04
#define SERIAL_FIFO_14_BYTE_THRESHOLD 0xC0

#define SERIAL_MODEM_DTR 0x01
#define SERIAL_MODEM_RTS 0x02
#define SERIAL_MODEM_OUT1 0x04
#define SERIAL_MODEM_OUT2 0x08
#define SERIAL_MODEM_LOOPBACK 0x10

#define SERIAL_LSR_DATA_READY 0x01
#define SERIAL_LSR_OVERRUN_ERROR 0x02
#define SERIAL_LSR_PARITY_ERROR 0x04
#define SERIAL_LSR_FRAMING_ERROR 0x08
#define SERIAL_LSR_BREAK_INDICATOR 0x10
#define SERIAL_LSR_TX_EMPTY 0x20
#define SERIAL_LSR_TX_IDLE 0x40

#define MAX_SERIAL_PORTS 4
#define SERIAL_BASE_CLOCK 115200

static serial_port_t ports[MAX_SERIAL_PORTS] = {0};
static uint16_t default_output_port = COM1;

static inline void outb(uint16_t port, uint8_t value) {
  asm volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
  uint8_t value;
  asm volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
  return value;
}

static int get_port_index(uint16_t port) {
  switch (port) {
  case COM1:
    return 0;
  case COM2:
    return 1;
  case COM3:
    return 2;
  case COM4:
    return 3;
  default:
    return -1;
  }
}

static serial_port_t *get_port_struct(uint16_t port) {
  int index = get_port_index(port);
  return (index >= 0) ? &ports[index] : NULL;
}

void serial_configure(uint16_t port, uint32_t baud_rate, uint8_t data_bits,
                      uint8_t stop_bits, uint8_t parity) {
  serial_port_t *port_struct = get_port_struct(port);
  if (!port_struct)
    return;

  outb(SERIAL_LINE_CTRL_REG(port), 0x00);
  outb(SERIAL_FIFO_CTRL_REG(port), 0x00);
  outb(SERIAL_MODEM_CTRL_REG(port), 0x00);

  uint16_t divisor = SERIAL_BASE_CLOCK / baud_rate;

  outb(SERIAL_LINE_CTRL_REG(port), SERIAL_LINE_DLAB);
  outb(SERIAL_DIVISOR_LSB(port), divisor & 0xFF);
  outb(SERIAL_DIVISOR_MSB(port), (divisor >> 8) & 0xFF);

  uint8_t line_control = data_bits | stop_bits | parity;
  outb(SERIAL_LINE_CTRL_REG(port), line_control);

  outb(SERIAL_FIFO_CTRL_REG(port), SERIAL_FIFO_ENABLE | SERIAL_FIFO_CLEAR_RX |
                                       SERIAL_FIFO_CLEAR_TX |
                                       SERIAL_FIFO_14_BYTE_THRESHOLD);

  outb(SERIAL_MODEM_CTRL_REG(port),
       SERIAL_MODEM_DTR | SERIAL_MODEM_RTS | SERIAL_MODEM_OUT2);

  outb(SERIAL_MODEM_CTRL_REG(port), SERIAL_MODEM_DTR | SERIAL_MODEM_RTS |
                                        SERIAL_MODEM_OUT1 | SERIAL_MODEM_OUT2 |
                                        SERIAL_MODEM_LOOPBACK);
  outb(SERIAL_DATA_REG(port), 0xAE);

  if (inb(SERIAL_DATA_REG(port)) != 0xAE) {
    port_struct->initialized = false;
    return;
  }

  outb(SERIAL_MODEM_CTRL_REG(port),
       SERIAL_MODEM_DTR | SERIAL_MODEM_RTS | SERIAL_MODEM_OUT2);

  port_struct->port = port;
  port_struct->baud_rate = baud_rate;
  port_struct->data_bits = data_bits;
  port_struct->stop_bits = stop_bits;
  port_struct->parity = parity;
  port_struct->initialized = true;
  port_struct->fifo_enabled = true;
}

void serial_init(uint16_t port, uint32_t baud_rate) {
  serial_configure(port, baud_rate, SERIAL_DATA_8BITS, SERIAL_STOP_1BIT,
                   SERIAL_PARITY_NONE);
}

bool serial_transmit_empty(uint16_t port) {
  return (inb(SERIAL_LINE_STATUS_REG(port)) & SERIAL_LSR_TX_EMPTY) != 0;
}

bool serial_received(uint16_t port) {
  return (inb(SERIAL_LINE_STATUS_REG(port)) & SERIAL_LSR_DATA_READY) != 0;
}

void serial_putchar(uint16_t port, char c) {
  serial_port_t *port_struct = get_port_struct(port);
  if (!port_struct || !port_struct->initialized)
    return;

  while (!serial_transmit_empty(port))
    ;
  outb(SERIAL_DATA_REG(port), c);
}

char serial_getchar(uint16_t port) {
  serial_port_t *port_struct = get_port_struct(port);
  if (!port_struct || !port_struct->initialized)
    return 0;

  while (!serial_received(port))
    ;
  return inb(SERIAL_DATA_REG(port));
}

void serial_write(uint16_t port, const char *data, size_t size) {
  serial_port_t *port_struct = get_port_struct(port);
  if (!port_struct || !port_struct->initialized)
    return;

  for (size_t i = 0; i < size; i++) {
    if (data[i] == '\n') {
      serial_putchar(port, '\r');
    }
    serial_putchar(port, data[i]);
  }
}

void serial_writestring(uint16_t port, const char *str) {
  serial_write(port, str, strlen(str));
}

bool serial_is_initialized(uint16_t port) {
  serial_port_t *port_struct = get_port_struct(port);
  return port_struct && port_struct->initialized;
}

void serial_set_output_port(uint16_t port) {
  if (serial_is_initialized(port)) {
    default_output_port = port;
  }
}

uint16_t serial_get_output_port(void) { return default_output_port; }
