; ============================================
; CLEAN / HARMLESS ASM - FOR SCANNER TESTING
; This is a simple "Hello World" program.
; Should score LOW on the scanner.
; ============================================

section .data
    msg db 'Hello, World!', 0x0a
    len equ $ - msg

section .text
global _start

_start:
    ; write(stdout, msg, len)
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    lea rsi, [rel msg]
    mov rdx, len
    syscall

    ; exit(0)
    mov rax, 60         ; sys_exit
    xor rdi, rdi
    syscall
