#ifndef SERIAL_H
#define SERIAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define COM1 0x3F8
#define COM2 0x2F8
#define COM3 0x3E8
#define COM4 0x2E8

#define SERIAL_BAUD_115200 115200
#define SERIAL_BAUD_57600  57600
#define SERIAL_BAUD_38400  38400
#define SERIAL_BAUD_19200  19200
#define SERIAL_BAUD_9600   9600

#define SERIAL_DATA_5BITS 0x00
#define SERIAL_DATA_6BITS 0x01
#define SERIAL_DATA_7BITS 0x02
#define SERIAL_DATA_8BITS 0x03

#define SERIAL_STOP_1BIT  0x00
#define SERIAL_STOP_2BITS 0x04

#define SERIAL_PARITY_NONE  0x00
#define SERIAL_PARITY_ODD   0x08
#define SERIAL_PARITY_EVEN  0x18
#define SERIAL_PARITY_MARK  0x28
#define SERIAL_PARITY_SPACE 0x38

typedef struct {
    uint16_t port;
    uint32_t baud_rate;
    uint8_t data_bits;
    uint8_t stop_bits;
    uint8_t parity;
    bool initialized;
    bool fifo_enabled;
} serial_port_t;

void serial_init(uint16_t port, uint32_t baud_rate);
void serial_configure(uint16_t port, uint32_t baud_rate, uint8_t data_bits, uint8_t stop_bits, uint8_t parity);
void serial_putchar(uint16_t port, char c);
void serial_write(uint16_t port, const char *data, size_t size);
void serial_writestring(uint16_t port, const char *str);
char serial_getchar(uint16_t port);
bool serial_received(uint16_t port);
bool serial_transmit_empty(uint16_t port);
bool serial_is_initialized(uint16_t port);

void serial_set_output_port(uint16_t port);
uint16_t serial_get_output_port(void);

#endif
