#include <windows.h>
#include <stdio.h>

void execute(PVOID shellcode_mem) {
    const char* cmd = (const char*)shellcode_mem;
    char temp_path[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, temp_path);
    char out_file[MAX_PATH] = {0};
    lstrcpyA(out_file, temp_path);
    lstrcatA(out_file, "cp_cmd_output.txt");

    char params[2048] = {0};
    lstrcpyA(params, "/c \"");
    lstrcatA(params, cmd);
    lstrcatA(params, "\" > \"");
    lstrcatA(params, out_file);
    lstrcatA(params, "\"");

    char debug_file[MAX_PATH] = {0};
    lstrcpyA(debug_file, temp_path);
    lstrcatA(debug_file, "cp_cmd_params.txt");
    HANDLE hDbg = CreateFileA(debug_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDbg != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hDbg, params, lstrlenA(params), &written, NULL);
        CloseHandle(hDbg);
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessA(
            "C:\\Windows\\System32\\cmd.exe",
            params,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        if (GetFileAttributesA(out_file) != INVALID_FILE_ATTRIBUTES) {
            ShellExecuteA(NULL, "open", out_file, NULL, NULL, SW_SHOWNORMAL);
        }
    }
}
