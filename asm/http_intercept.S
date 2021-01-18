.GLOBL main

main:
    movq $0xaabbccddeeff1122, %r8
    jmp *%r8
    nop
    nop
    nop
    nop