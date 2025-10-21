#ifndef KEYBOARD_H
#define KEYBOARD_H

#include <stdint.h>
#include <stdbool.h>

#define KEYBOARD_DATA_PORT    0x60
#define KEYBOARD_STATUS_PORT  0x64
#define KEYBOARD_COMMAND_PORT 0x64

#define SCANCODE_RELEASED     0x80

#define KEY_LSHIFT   0x2A
#define KEY_RSHIFT   0x36
#define KEY_LCTRL    0x1D
#define KEY_LALT     0x38
#define KEY_CAPS     0x3A
#define KEY_F1       0x3B
#define KEY_F2       0x3C
#define KEY_F3       0x3D
#define KEY_F4       0x3E
#define KEY_F5       0x3F
#define KEY_F6       0x40
#define KEY_F7       0x41
#define KEY_F8       0x42
#define KEY_F9       0x43
#define KEY_F10      0x44
#define KEY_ESC      0x01
#define KEY_BACKSPACE 0x0E
#define KEY_TAB      0x0F
#define KEY_ENTER    0x1C
#define KEY_SPACE    0x39

typedef struct {
    bool shift_pressed;
    bool ctrl_pressed;
    bool alt_pressed;
    bool caps_lock_on;
} keyboard_state_t;

void keyboard_init(void);
void keyboard_handle_interrupt(void);
char keyboard_scancode_to_ascii(uint8_t scancode, bool shift);
void keyboard_set_leds(bool caps, bool num, bool scroll);

extern keyboard_state_t keyboard_state;

#endif