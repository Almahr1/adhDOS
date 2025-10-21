#include <kernel/keyboard.h>
#include <kernel/tty.h>
#include <stdint.h>
#include <stdio.h>

keyboard_state_t keyboard_state = {0};

static const char scancode_to_ascii[128] = {
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '-', '=', '\b',
    '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p',
    '[', ']', '\n',
    0,
    'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',
    '\'', '`',   0,
    '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/',   0,
    '*',
    0,
    ' ',
    0,
    0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0,
    0,
    0,
    0,
    0,
    0,
    '-',
    0,
    0,
    0,
    '+',
    0,
    0,
    0,
    0,
    0,
    0, 0, 0,
    0,
    0,
    0,
};

static const char scancode_to_ascii_shift[128] = {
    0,  27, '!', '@', '#', '$', '%', '^', '&', '*',
    '(', ')', '_', '+', '\b',
    '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P',
    '{', '}', '\n',
    0,
    'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',
    '"', '~',   0,
    '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?',   0,
    '*',
    0,
    ' ',
    0,
    0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0,
    0,
    0,
    0,
    0,
    0,
    '-',
    0,
    0,
    0,
    '+',
    0,
    0,
    0,
    0,
    0,
    0, 0, 0,
    0,
    0,
    0,
};

void keyboard_init(void) {
    keyboard_state.shift_pressed = false;
    keyboard_state.ctrl_pressed = false;
    keyboard_state.alt_pressed = false;
    keyboard_state.caps_lock_on = false;
    
    printf("Keyboard driver initialized\n");
}

char keyboard_scancode_to_ascii(uint8_t scancode, bool shift) {
    if (scancode >= 128) {
        return 0;
    }
    
    if (shift || keyboard_state.caps_lock_on) {
        char ch = scancode_to_ascii_shift[scancode];
        if (keyboard_state.caps_lock_on && !shift) {
            if (ch >= 'A' && ch <= 'Z') {
                return ch;
            } else if (scancode_to_ascii[scancode] >= 'a' && scancode_to_ascii[scancode] <= 'z') {
                return scancode_to_ascii[scancode] - 'a' + 'A';
            }
        }
        return ch;
    }
    
    return scancode_to_ascii[scancode];
}

void keyboard_set_leds(bool caps, bool num, bool scroll) {
    uint8_t led_state = 0;
    if (caps) led_state |= 0x04;
    if (num) led_state |= 0x02;
    if (scroll) led_state |= 0x01;
    
    asm volatile("outb %0, %1" : : "a"((uint8_t)0xED), "Nd"((uint16_t)KEYBOARD_DATA_PORT));
    asm volatile("outb %0, %1" : : "a"(led_state), "Nd"((uint16_t)KEYBOARD_DATA_PORT));
}

void keyboard_handle_interrupt(void) {
    uint8_t scancode;
    asm volatile("inb %1, %0" : "=a"(scancode) : "Nd"((uint16_t)KEYBOARD_DATA_PORT));
    
    bool key_released = scancode & SCANCODE_RELEASED;
    if (key_released) {
        scancode &= ~SCANCODE_RELEASED;
    }
    
    switch (scancode) {
        case KEY_LSHIFT:
        case KEY_RSHIFT:
            keyboard_state.shift_pressed = !key_released;
            break;
            
        case KEY_LCTRL:
            keyboard_state.ctrl_pressed = !key_released;
            break;
            
        case KEY_LALT:
            keyboard_state.alt_pressed = !key_released;
            break;
            
        case KEY_CAPS:
            if (!key_released) {
                keyboard_state.caps_lock_on = !keyboard_state.caps_lock_on;
                keyboard_set_leds(keyboard_state.caps_lock_on, false, false);
            }
            break;
            
        case KEY_F1:
            if (!key_released) {
                printf("[F1 pressed]\n");
            }
            break;
            
        case KEY_F2:
            if (!key_released) {
                printf("[F2 pressed]\n");
            }
            break;
            
        case KEY_ESC:
            if (!key_released) {
                printf("[ESC pressed]\n");
            }
            break;
            
        default:
            if (!key_released) {
                char ascii = keyboard_scancode_to_ascii(scancode, keyboard_state.shift_pressed);
                if (ascii != 0) {
                    if (keyboard_state.ctrl_pressed) {
                        printf("^%c", ascii);
                    } else if (keyboard_state.alt_pressed) {
                        printf("Alt+%c", ascii);
                    } else {
                        terminal_putchar(ascii);
                    }
                } else {
                    printf("[Unknown key: 0x%x]\n", scancode);
                }
            }
            break;
    }
}