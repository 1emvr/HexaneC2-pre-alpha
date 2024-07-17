global inj_Start
global inj_InstStart
global inj_InstEnd
extern inj_Entrypoint

section .text$A
    inj_Start:
        push    rsi
        mov     rsi, rsp
        and     rsp, 0xFFFFFFFFFFFFFFF0
        sub     rsp, 0x20
        call    Entrypoint
        mov     rsp, rsi
        pop     rsi
        ret

    inj_InstStart:
        call    RetStartPtr
        ret

    inj_RetStartPtr:
        mov     rax, [rsp]
        sub     rax, 0x1B
        ret

section .text$E
    inj_InstEnd:
        call    RetEndPtr
        ret

    inj_RetEndPtr:
        mov     rax, [rsp]
        add     rax, 0x0A
        ret