.data



.code

;we want to somehow get this function to be inline with native C++ code despite documentation stating it shouldnt be possible.. x86 is of course no problem
;basic design to trick decompilers into thinking the function is something which it isnt. For example, the below will cause 'IDA Free' software to assume it has one argument, and returns the first argument as the only statement. The 'arg_0' will point to undefined/error memory.
InlineMeTest PROC

	push rsp ;push return addr
  sub rsp, 8 ;keep the stack from moving
  
  ;other logic goes here, perhaps call some other function
  
	mov rsp, rsp //junk instruction
	mov rax, [rsp+10h] //jumps back to return address, thus 'returns' the return address and not the 'first argument'.
	jmp rax

InlineMeTest ENDP
;it would be ideal to create some 'function prototype' which includes a templated return value and decompilation corruption

END
