#pragma once
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define SEED 5

// 1. Compile-time Seed Generation
constexpr int RandomCompileTimeSeed(void) {
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
}

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;

// 2. Hashing Functions (constexpr must be in header)
constexpr DWORD HashStringDjb2W(const wchar_t* String) {
    ULONG Hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }
    return Hash;
}

constexpr DWORD HashStringDjb2A(const char* String) {
    ULONG Hash = (ULONG)g_KEY;
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }
    return Hash;
}

// 3. Macros
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)

#define CTIME_HASHA( API ) constexpr auto API##_Hash = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Hash = HashStringDjb2W((const wchar_t*) L#API);

// 4. Function Prototype
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);