    pop     rax
    sub     rax, 0x05
    push    rax
    push    rcx
    push    rdx
    push    r8
    push    r9
    push    r10
    push    r11
    mov     rcx, 0xBAADF00DBAADF00D
    mov     [rax], rcx
    sub     rsp, 0x40
    call    Payload
    add     rsp, 0x40
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdx
    pop     rcx
    pop     rax
    jmp     rax
Payload: