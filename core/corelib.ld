LINK_BASE = 0x0000;
ENTRY(Start)
SECTIONS {
    . = LINK_BASE;

    .text : {
        . = LINK_BASE;
        *(.corelib.text$A);
        *(.corelib.text$B);
        *(.corelib.rdata*);

        FILL(0X00);
        . = ALIGN(0x1000);
        __CoreInstance = .;

        *(.corelib.global);
        *(.corelib.text$E);
        *(.corelib.text$F);
    }

    .eh_frame : {
        *(.eh_frame)
    }
}