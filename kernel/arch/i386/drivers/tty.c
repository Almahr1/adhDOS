#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "vga.h"
#include <kernel/tty.h>

static const size_t VGAWIDTH = 80;
static const size_t VGAHEIGHT = 25;
static uint16_t *const VGAMEMORY = (uint16_t *)0xB8000;

static size_t terminal_row;
static size_t terminal_column;
static uint8_t terminal_color;
static uint16_t *terminal_buffer;

void terminal_initialize(void) {
  terminal_row = 0;
  terminal_column = 0;
  terminal_color = vga_entry_color(VGA_COLOR_LIGHT_GREY, VGA_COLOR_BLACK);
  terminal_buffer = VGAMEMORY;
  for (size_t x = 0; x < VGAWIDTH; x++) {
    for (size_t y = 0; y < VGAHEIGHT; y++) {
      const size_t index = y * VGAWIDTH + x;
      terminal_buffer[index] = vga_entry(' ', terminal_color);
    }
  }
}

void terminal_scroll(void) {
  // Move all lines up by one
  for (size_t y = 0; y < VGAHEIGHT - 1; y++) {
    for (size_t x = 0; x < VGAWIDTH; x++) {
      const size_t dst_index = y * VGAWIDTH + x;
      const size_t src_index = (y + 1) * VGAWIDTH + x;
      terminal_buffer[dst_index] = terminal_buffer[src_index];
    }
  }

  // Clear the last line
  for (size_t x = 0; x < VGAWIDTH; x++) {
    const size_t index = (VGAHEIGHT - 1) * VGAWIDTH + x;
    terminal_buffer[index] = vga_entry(' ', terminal_color);
  }
}

void terminal_putchar(char c) {
  if (c == '\n') { // Newline
    terminal_column = 0;
    if (++terminal_row == VGAHEIGHT) {
      terminal_scroll();
      terminal_row = VGAHEIGHT - 1;
    }
  } else if (c == '\r') { // Carriage return
    terminal_column = 0;
  } else if (c == '\b') { // Backspace
    if (terminal_column > 0) {
      terminal_column--;
    } else if (terminal_row > 0) {
      terminal_row--;
      terminal_column = VGAWIDTH - 1;
    }
    const size_t index = terminal_row * VGAWIDTH + terminal_column;
    terminal_buffer[index] = vga_entry(' ', terminal_color);
  } else {
    const size_t index = terminal_row * VGAWIDTH + terminal_column;
    terminal_buffer[index] = vga_entry(c, terminal_color);
    if (++terminal_column == VGAWIDTH) {
      terminal_column = 0;
      if (++terminal_row == VGAHEIGHT) {
        terminal_scroll();
        terminal_row = VGAHEIGHT - 1;
      }
    }
  }
}

void terminal_write(const char *data, size_t size) {
  for (size_t i = 0; i < size; i++) {
    terminal_putchar(data[i]);
  }
}

void terminal_writestring(const char *data) {
  terminal_write(data, strlen(data));
}
