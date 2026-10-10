.text
.globl _start
.type _start,@function
_start:
    xor %rbp, %rbp
    mov (%rsp), %rdi
    lea 8(%rsp), %rsi
    call portable_main
    mov %eax, %edi
    mov $60, %eax
    syscall
    hlt
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
