    .text
    .globl do_indirect_syscall
    .globl g_syscall_gadget
    .globl g_ssn

do_indirect_syscall:
    mov    %rcx, %r10
    mov    g_ssn(%rip), %eax
    jmp    *g_syscall_gadget(%rip)

    .data
    .globl g_syscall_gadget
    .globl g_ssn
g_syscall_gadget:
    .quad 0
g_ssn:
    .long 0
