LINK_BASE = 0x0000;
ENTRY(Start)

SECTIONS {
    . = LINK_BASE;

    .text : {
        . = LINK_BASE;

        *(.text$A);
        *(.text$B);
        *(.data*);
        *(.rdata*);

        FILL(0X00);
        . = ALIGN(0x1000);

        __global = .;
        *(.global);
        *(.text$E);
        *(.text$F);
    }
    .eh_frame : {
        *(.eh_frame)
    }
}
