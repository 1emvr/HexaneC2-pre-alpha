LINK_BASE = 0x0000;
ENTRY(Start)
SECTIONS {
    . = LINK_BASE;

    .text : {
        . = LINK_BASE;
        *(.injectlib.text$A);
        *(.injectlib.text$B);
        *(.injectlib.rdata*);

        FILL(0X00);
        . = ALIGN(0x1000);
        __InjectInstance = .;

        *(.injectlib.global);
        *(.injectlib.text$E);
        *(.injectlib.text$F);
    }

    .eh_frame : {
        *(.eh_frame)
    }
}