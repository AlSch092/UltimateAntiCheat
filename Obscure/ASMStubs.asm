.data


.code

VM_Jmp PROC ;  VM_Jmp(UINT callAddress)  - ** This routine is not finished yet **

    jmp rcx

VM_Jmp ENDP


; rcx = call addr
; rdx = num parameters
; r8 = parameter list
VM_Call PROC

    push rax
    push r11
    push r12
    push r13

    mov r11, rcx ; move callAddress into rax, shift all parameters into correct registers
    mov eax, edx ; move num parameters into ax
    mov r13, [rsp+20h]
    mov r12, r8 ;copy parameter list into r12 since we may overwrite r8
    mov rcx, r8
    mov rdx, r9

p_loop:
    cmp eax, 0  ;if 0 parameters, jmp to call routine
    je to_call
    cmp ax, 1
    jne p2
    mov rcx, [r12]
    dec ax
    jmp p_loop
p2:
    cmp ax, 2
    jne p3
    mov rdx, [r12+08h]
    dec ax
    jmp p_loop
p3:
    cmp ax, 3
    jne p4
    mov r8, [r12 + 10h]
    dec ax
    jmp p_loop
p4:
    cmp ax, 4
    jg p_above4
    mov r9, [r12 + 18h]
    dec ax
    jmp p_loop
p_above4:
    push r14
    push r15
    mov r14w, ax
    imul r14, 08h
    sub r14, 08h
    mov r15, [r12 + r14] ; move n-th parameter (above 5) into r15
    add r14, 10h ;make up for the two pushes above
    mov [rsp+r14], r15
    pop r15
    pop r14
    dec ax
    jmp p_loop

to_call:
    sub rsp, 28h
    call r11
    add rsp, 28h

    pop r12
    pop r11
    add rsp,08h  ; instead of pop rax, just add 8 to rsp to avoid muddying return value
    mov [rsp+08h], r13
    pop r13
    ret

VM_Call ENDP

END