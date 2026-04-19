#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

#include "Structs.h" 

 // --- Macros / Constants ---
#define FLG_HEAP_ENABLE_TAIL_CHECK    0x10
#define FLG_HEAP_ENABLE_FREE_CHECK    0x20
#define FLG_HEAP_VALIDATE_PARAMETERS  0x40
#define BLACKLISTARRAY_SIZE           5

// --- Typedefs ---
typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

// --- Function Prototypes ---

// PEB Checks
BOOL IsDebuggerPresent2();
BOOL IsDebuggerPresent3();

// System API Checks
BOOL NtQIPDebuggerCheck();
BOOL OutputDebugStringCheck();

// CPU / Thread Checks
BOOL HardwareBpCheck();
BOOL DebugBreakCheck();

// Environment Checks
BOOL BlackListedProcessesCheck();

// Timing Checks
BOOL TimeTickCheck1();
BOOL TimeTickCheck2();
