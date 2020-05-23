
.global elf_lazy_resolve_stub
elf_lazy_resolve_stub:
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10

    // push n
    // push GOT[1]
    pop %rdi // GOT[1]
    pop %rsi // n

    call elf_lazy_resolve

    mov %rax, %r11

    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi

    jmp *%r11

