; boot.s - Multiboot Entry Point for Milla OS
[BITS 32]

section .text
align 4

extern kernel_main
global _start

_start:
    ; GRUB puts magic in EAX and info pointer in EBX
    ; We need to set up a stack before calling C++ code
    cli
    mov esp, stack_top
    
    ; Pass arguments to kernel_main(uint32_t magic, multiboot_info* info)
    push ebx ; info
    push eax ; magic
    
    call kernel_main

    ; Fallback: infinite loop if kernel_main returns
.halt:
    hlt
    jmp .halt

section .bss
align 16
stack_bottom:
    resb 16384 ; 16 KB Stack
stack_top:
