LINK_BASE = 0x0000;
SECTIONS {
    . = LINK_BASE;

    .text : {
        . = LINK_BASE;
        *(.text$B);
        *(.data*);
        *(.rdata*);
    }
}