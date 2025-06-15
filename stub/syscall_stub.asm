.code

syscall_gate PROC
    mov r10, rcx    ; Preserve original RCX (first syscall argument) in R10, like ntdll stubs do.
                    ; EAX should already contain the syscall number (set by the C wrapper).
    syscall         ; Perform the system call.
    ret             ; Return to the C wrapper.
syscall_gate ENDP

END 