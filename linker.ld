OUTPUT_FORMAT(elf32-i386)
ENTRY(kernel_main)

SECTIONS {
    . = 0x100000;

    .text : {
        *(.multiboot_header)
        *(.text)
    }

    .rodata : {
        *(.rodata)
    }

    .data : {
        *(.data)
    }

    .bss : {
        *(.bss)
    }
}

