global Start
global InstStart
global InstEnd
extern Entrypoint

section .text$A
    Start:
        push    rsi
        mov     rsi, rsp
        and     rsp, 0xFFFFFFFFFFFFFFF0
        sub     rsp, 0x20
        call    Entrypoint
        mov     rsp, rsi
        pop     rsi
        ret

    InstStart:
        call    RetStartPtr
        ret

    RetStartPtr:
        mov     rax, [rsp]
        sub     rax, 0x1B
        ret

section .text$E
    InstEnd:
        call    RetEndPtr
        ret

    RetEndPtr:
        mov     rax, [rsp]
        add     rax, 0x0A
        ret