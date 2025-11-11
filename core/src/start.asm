global Start
extern Entrypoint

section .text
    Start:
        push 	rsi
        mov 	rsi, rsp
        and 	rsp, 0xFFFFFFFFFFFFFFF0
        sub 	rsp, 0x20
        call 	Entrypoint
        mov 	rsp, rsi
        pop 	rsi
        ret
