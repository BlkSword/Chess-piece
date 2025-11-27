
#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((LONG)(Status) >= 0)
#endif

// AES-GCM Decryption using Windows CNG
BOOL decrypt_aes(BYTE* shellcode, DWORD shellcode_len, BYTE* key, DWORD key_len) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return FALSE;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, key_len, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    memset(&authInfo, 0, sizeof(authInfo));
    authInfo.cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO);
    authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;

    BYTE nonce[] = "uniquestring"; // 12-byte nonce
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = 12;

    if (shellcode_len < 16) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    DWORD data_len = shellcode_len - 16;
    authInfo.pbTag = shellcode + data_len;
    authInfo.cbTag = 16;

    DWORD decrypted_len = 0;
    status = BCryptDecrypt(hKey, shellcode, data_len, &authInfo, NULL, 0, shellcode, data_len, &decrypted_len, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return NT_SUCCESS(status);
}

// RC4 Decryption
void decrypt_rc4(BYTE* data, DWORD data_len, BYTE* key, DWORD key_len) {
    int i = 0, j = 0;
    BYTE s[256];
    for (int k = 0; k < 256; k++) s[k] = k;

    for (int k = 0; k < 256; k++) {
        j = (j + s[k] + key[k % key_len]) % 256;
        BYTE temp = s[k];
        s[k] = s[j];
        s[j] = temp;
    }

    for (DWORD k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        BYTE temp = s[i];
        s[i] = s[j];
        s[j] = temp;
        data[k] ^= s[(s[i] + s[j]) % 256];
    }
}

// XOR Decryption
void decrypt_xor(BYTE* data, DWORD data_len, BYTE* key, DWORD key_len) {
    for (DWORD i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}
