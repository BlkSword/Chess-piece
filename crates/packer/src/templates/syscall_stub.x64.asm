
.code

SyscallStub PROC
    mov r10, rcx
    mov eax, r8d
    syscall
    ret
SyscallStub ENDP

END
