.code

; Export the functions
PUBLIC syscall_stub
PUBLIC do_syscall

; Syscall stub for x64 Windows
; Expects syscall ID in EAX, arguments according to x64 ABI (RCX, RDX, R8, R9, stack)
; RCX needs to be moved to R10 for syscall convention
syscall_stub proc
    mov r10, rcx    ; Move first argument to R10 as required by syscall convention
    ; Syscall ID is expected to be already in EAX before calling this stub
    syscall         ; Make the system call
    ret             ; Return to caller
syscall_stub endp

; do_syscall - Executes a syscall with the given syscall ID and parameters
; Arguments (Windows x64 calling convention):
;   RCX = syscall ID
;   RDX = arg1
;   R8  = arg2  
;   R9  = arg3
;   [RSP+28h] = arg4
;   [RSP+30h] = arg5
;   ... additional args on stack
;
; The Windows x64 syscall convention:
;   RAX = syscall number
;   R10 = RCX (first argument)
;   RDX, R8, R9 remain as-is
;   Additional arguments are on the stack

do_syscall PROC
    ; Save the syscall ID from RCX to RAX
    mov rax, rcx
    
    ; Move first argument from RDX to R10 (Windows syscall convention)
    mov r10, rdx
    
    ; RDX = R8 (shift arguments)
    mov rdx, r8
    
    ; R8 = R9 (shift arguments)
    mov r8, r9
    
    ; R9 = [RSP+28h] (5th argument from stack)
    mov r9, [rsp+28h]
    
    ; Perform the syscall
    syscall
    
    ; Return (result is already in RAX)
    ret
do_syscall ENDP

end 