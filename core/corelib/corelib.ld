LINK_BASE = 0x0000;
ENTRY(Start)
SECTIONS {
    . = LINK_BASE;

    .text : {
        . = LINK_BASE;
        *(.text$B);
    }

    .eh_frame : {
        *(.eh_frame)
    }
}