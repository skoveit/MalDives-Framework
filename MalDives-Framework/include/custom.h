#pragma once
#include <windows.h>

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName);
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName);

FARPROC GetProcAddressH(IN HMODULE hModule, IN LPCSTR lpApiName);
HMODULE GetModuleHandleH(IN LPCWSTR szModuleName);

