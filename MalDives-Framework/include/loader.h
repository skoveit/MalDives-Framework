#pragma once
#include <windows.h>

BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize);
BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress);
BOOL RemoteMapInject(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress);
BOOL LocalFunctionStomping(PVOID pPayload, SIZE_T sPayloadSize);
BOOL RemoteFunctionStomping(HANDLE hProcess, PVOID pPayload, SIZE_T sPayloadSize, LPCSTR DLLName, LPCSTR FunctionName);