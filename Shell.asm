.data
hello_msg db "Hello world", 0
info_msg  db "Info", 0

.code

EXTERN GetForegroundWindow: PROC
EXTERN MessageBoxA: PROC

inline_code macro
     
     push rbp
     mov rbp, rsp
     xor rax, rax
     jz lol
     db 0eah
     lol:
     pop rbp
     ret
ENDM

inline_test PROC
    inline_code
inline_test ENDP

; using [rsp+8, 0x10] etc will trick IDA into thinking the function has parameters if it otherwise does not..
; this will trick ida into thinking rsp+8 is a function ptr, then it returns the call value of this function ptr 
MisleadingFunction PROC

	push rsp
	sub rsp, 8
	mov rsp, rsp
	mov rax, [rsp+10h]
    inline_code
	jmp rax

MisleadingFunction ENDP

_MessageBox PROC
    push rbp
    mov rbp,rsp
    sub rsp,40h
    xor rcx, rcx
    mov rdx, 0
    mov r8, 0
    mov r9, 0 ; MB_OK
    call MessageBoxA
    add rsp, 40h
    mov rsp,rbp
    pop rbp
    ret
_MessageBox ENDP

;this example can grow very much in complexity
;for example, we should add in a 'return address' check to ensure someone hasent hooked this routine or possibly the routine which called this
;we must get it to a point such that emulation is very difficult. 

shellxor PROC
    push rsp
    sub rsp, 80h
    push rcx
    mov al, 8
    mov rcx, 1111; this number is usually sent by the server
    mov rdx, 1337h ; this one also can be sent by server, but for now we'll keep it as a const


    ;cmp [rsp+90h], g_ImageBase


    xor rcx, rdx ; operation
    add rdx, 1234h ; makes things trickier, we add to the 'constant' some other constant. simply xoring the same thing 8 times isn't useful
    test     al, al
    dec al

    jne $ - 0Eh ;jump back upwards 8 times (size of uint64_t), the 8 can be changed to anything really
    mov rax, rcx
    pop rcx
    add     rsp, 80h
    pop rsp
    ret 
shellxor ENDP

END