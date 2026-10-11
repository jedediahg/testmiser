.text
.global _start
.type _start,@function
_start:
    mov %rsp, %rdi
    call tm_device_probe_start
    ud2
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
