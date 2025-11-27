
#if defined(_M_X64)

// Structure to hold syscall information
typedef struct {
    DWORD ssn;
    PVOID syscall_address;
} SYSCALL_INFO;

// Function to get the SSN and syscall address from a ntdll function
BOOL get_ssn(LPCSTR function_name, SYSCALL_INFO* syscall_info) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return FALSE;

    FARPROC pFunction = GetProcAddress(hNtdll, function_name);
    if (pFunction == NULL) return FALSE;

    // Find the syscall instruction
    for (int i = 0; i < 32; i++) {
        // Look for mov r10, rcx
        if (*((PBYTE)pFunction + i) == 0x4c && *((PBYTE)pFunction + i + 1) == 0x8b && *((PBYTE)pFunction + i + 2) == 0xd1) {
            // Look for mov eax, ssn
            if (*((PBYTE)pFunction + i + 3) == 0xb8) {
                syscall_info->ssn = *((PDWORD)(pFunction + i + 4));
                syscall_info->syscall_address = (PVOID)(pFunction + i);
                return TRUE;
            }
        }
    }
    return FALSE;
}

// The actual syscall stub is defined in a separate .asm file or using intrinsics.
// For simplicity, we declare it as an external function.
EXTERN_C PVOID SyscallStub(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, DWORD);

#endif
