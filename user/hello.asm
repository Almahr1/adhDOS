[org 0x400000]
bits 32

_start:
    mov eax, 4
    mov ebx, 1
    mov ecx, msg
    mov edx, msg_len
    int 0x80

    mov eax, 1
    xor ebx, ebx
    int 0x80

    jmp $

msg:     db "Hello from userspace!", 10
msg_len: equ $ - msg
