#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool print(const char *data, size_t length) {
  const unsigned char *bytes = (const unsigned char *)data;
  for (size_t i = 0; i < length; i++)
    if (putchar(bytes[i]) == EOF)
      return false;
  return true;
}

static int print_int(unsigned int n, int base, int min_width, char pad_char,
                     bool is_signed, int value) {
  char buffer[32];
  char *ptr = &buffer[31];
  *ptr = '\0';

  bool is_negative = false;
  if (is_signed && value < 0) {
    is_negative = true;
    n = (unsigned int)-value;
  }

  if (n == 0) {
    *--ptr = '0';
  }

  const char *digits = "0123456789abcdef";
  while (n > 0) {
    *--ptr = digits[n % base];
    n /= base;
  }

  if (is_negative) {
    *--ptr = '-';
  }

  int len = &buffer[31] - ptr;
  while (len < min_width) {
    *--ptr = pad_char;
    len++;
  }

  size_t final_len = &buffer[31] - ptr;
  if (!print(ptr, final_len)) {
    return -1;
  }
  return (int)final_len;
}

int printf(const char *restrict format, ...) {
  va_list parameters;
  va_start(parameters, format);

  int written = 0;

  while (*format != '\0') {
    size_t maxrem = INT_MAX - written;

    if (format[0] != '%' || format[1] == '%') {
      if (format[0] == '%')
        format++;
      size_t amount = 1;
      while (format[amount] && format[amount] != '%')
        amount++;
      if (maxrem < amount) {
        return -1;
      }
      if (!print(format, amount))
        return -1;
      format += amount;
      written += amount;
      continue;
    }

    const char *format_begun_at = format++;

    int min_width = 0;
    char pad_char = ' ';

    if (*format == '0') {
      pad_char = '0';
      format++;
    }

    while (*format >= '0' && *format <= '9') {
      min_width = min_width * 10 + (*format - '0');
      format++;
    }

    if (*format == 'c') {
      format++;
      char c = (char)va_arg(parameters, int);
      if (!maxrem) {
        return -1;
      }
      if (!print(&c, sizeof(c)))
        return -1;
      written++;
    } else if (*format == 's') {
      format++;
      const char *str = va_arg(parameters, const char *);
      size_t len = strlen(str);
      if (maxrem < len) {
        return -1;
      }
      if (!print(str, len))
        return -1;
      written += len;
    } else if (*format == 'd' || *format == 'i') {
      format++;
      int i = va_arg(parameters, int);
      int len = print_int((unsigned int)i, 10, min_width, pad_char, true, i);
      if (len < 0)
        return -1;
      written += len;
    } else if (*format == 'u') {
      format++;
      unsigned int i = va_arg(parameters, unsigned int);
      int len = print_int(i, 10, min_width, pad_char, false, 0);
      if (len < 0)
        return -1;
      written += len;
    } else if (*format == 'x') {
      format++;
      unsigned int i = va_arg(parameters, unsigned int);
      int len = print_int(i, 16, min_width, pad_char, false, 0);
      if (len < 0)
        return -1;
      written += len;
    } else if (*format == 'p') {
      format++;
      void *ptr = va_arg(parameters, void *);
      if (!print("0x", 2))
        return -1;
      written += 2;
      int len = print_int((unsigned int)ptr, 16, 8, '0', false, 0);
      if (len < 0)
        return -1;
      written += len;
    } else {
      format = format_begun_at;
      size_t len = strlen(format);
      if (maxrem < len) {
        return -1;
      }
      if (!print(format, len))
        return -1;
      written += len;
      format += len;
    }
  }

  va_end(parameters);
  return written;
}
