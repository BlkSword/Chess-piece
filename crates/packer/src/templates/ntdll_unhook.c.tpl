#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

PVOID GetDll(WCHAR* findname) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    
    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->FullDllName.Buffer && wcsstr(entry->FullDllName.Buffer, findname)) {
            return entry->DllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

BOOL UnhookNtdll() {
    // 创建挂起进程获取干净ntdll
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    BOOL result = CreateProcessA(
        NULL,
        "cmd.exe",
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        "C:\\Windows\\System32\\",
        &si,
        &pi
    );
    
    if (!result) {
        return FALSE;
    }
    
    // 获取当前进程和挂起进程的ntdll基址
    WCHAR findname[] = L"ntdll.dll\x00";
    PVOID localNtdll = GetDll(findname);
    
    // 在挂起进程中读取ntdll头信息
    IMAGE_DOS_HEADER dosHeader = {0};
    SIZE_T bytesRead = 0;
    
    NtReadVirtualMemory_t NtReadVirtualMemory_p = (NtReadVirtualMemory_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    
    if (NtReadVirtualMemory_p(pi.hProcess, localNtdll, &dosHeader, sizeof(dosHeader), &bytesRead) != 0) {
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // 读取NT头
    IMAGE_NT_HEADERS ntHeaders = {0};
    if (NtReadVirtualMemory_p(pi.hProcess, (PVOID)((DWORD_PTR)localNtdll + dosHeader.e_lfanew), 
        &ntHeaders, sizeof(ntHeaders), &bytesRead) != 0) {
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // 分配内存存储干净的ntdll
    DWORD ntdllSize = ntHeaders.OptionalHeader.SizeOfImage;
    LPVOID freshNtdll = VirtualAlloc(NULL, ntdllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!freshNtdll) {
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // 读取整个干净的ntdll
    if (NtReadVirtualMemory_p(pi.hProcess, localNtdll, freshNtdll, ntdllSize, &bytesRead) != 0) {
        VirtualFree(freshNtdll, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // 获取.text节区信息
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(&ntHeaders);
    PIMAGE_SECTION_HEADER textSection = NULL;
    
    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)sectionHeader[i].Name, ".text", 6) == 0) {
            textSection = &sectionHeader[i];
            break;
        }
    }
    
    if (!textSection) {
        VirtualFree(freshNtdll, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // 修改内存保护
    DWORD oldProtect;
    if (!VirtualProtect((PVOID)((DWORD_PTR)localNtdll + textSection->VirtualAddress), 
        textSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        VirtualFree(freshNtdll, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // 写入干净的.text节区
    NtWriteVirtualMemory_t NtWriteVirtualMemory_p = (NtWriteVirtualMemory_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    
    SIZE_T bytesWritten = 0;
    BOOL writeResult = NtWriteVirtualMemory_p(GetCurrentProcess(), 
        (PVOID)((DWORD_PTR)localNtdll + textSection->VirtualAddress),
        (PVOID)((DWORD_PTR)freshNtdll + textSection->VirtualAddress),
        textSection->Misc.VirtualSize, &bytesWritten) == 0;
    
    // 恢复原始保护
    VirtualProtect((PVOID)((DWORD_PTR)localNtdll + textSection->VirtualAddress), 
        textSection->Misc.VirtualSize, oldProtect, &oldProtect);
    
    // 清理
    VirtualFree(freshNtdll, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return writeResult;
}