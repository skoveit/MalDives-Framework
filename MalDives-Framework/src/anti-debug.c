#include "anti-debug.h"

BOOL IsDebuggerPresent2() {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	if (pPeb->BeingDebugged == 1)
		return TRUE;

	return FALSE;
}

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

BOOL IsDebuggerPresent3() {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	if (pPeb->NtGlobalFlag & (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS))
		return TRUE;

	return FALSE;
}


typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);



BOOL NtQIPDebuggerCheck() {

	NTSTATUS						STATUS = NULL;
	fnNtQueryInformationProcess		pNtQueryInformationProcess = NULL;
	DWORD64							dwIsDebuggerPresent = NULL;
	DWORD64							hProcessDebugObject = NULL;

	// getting NtQueryInformationProcess address
	pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		printf("\n\t[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calling NtQueryInformationProcess with the 'ProcessDebugPort' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugPort,
		&dwIsDebuggerPresent,
		sizeof(DWORD64),
		NULL
	);

	// if STATUS is not
	if (STATUS != 0x0) {
		printf("\n\t[!] NtQueryInformationProcess [1] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// if NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (dwIsDebuggerPresent != NULL) {
		//printf("\n\t[i] NtQueryInformationProcess [1] - ProcessDebugPort Detected A Debugger \n");
		return TRUE;
	}

	// calling NtQueryInformationProcess with the 'ProcessDebugObjectHandle' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugObjectHandle,
		&hProcessDebugObject,
		sizeof(DWORD64),
		NULL
	);

	// if STATUS is not 0 and not 0xC0000353 (that is 'STATUS_PORT_NOT_SET')
	if (STATUS != 0x0 && STATUS != 0xC0000353) {
		printf("\n\t[!] NtQueryInformationProcess [2] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// if NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (hProcessDebugObject != NULL) {
		//printf("\n\t[i] NtQueryInformationProcess [w] - hProcessDebugObject Detected A Debugger \n");
		return TRUE;
	}

	return FALSE;
}


BOOL HardwareBpCheck() {

	CONTEXT		Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext(GetCurrentThread(), &Ctx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// if one of these registers is not '0', then a hardware bp is installed
	if (Ctx.Dr0 != NULL || Ctx.Dr1 != NULL || Ctx.Dr2 != NULL || Ctx.Dr3 != NULL)
		return TRUE;

	return FALSE;
}


#define BLACKLISTARRAY_SIZE 5

WCHAR* g_BlackListedDebuggers[BLACKLISTARRAY_SIZE] = {
		L"x64dbg.exe",
		L"ida.exe",
		L"ida64.exe",
		L"VsDebugConsole.exe",
		L"msvsmon.exe"
};


BOOL BlackListedProcessesCheck() {

	HANDLE				hSnapShot = NULL;
	PROCESSENTRY32W		ProcEntry = { .dwSize = sizeof(PROCESSENTRY32W) };
	BOOL				bSTATE = FALSE;


	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32FirstW(hSnapShot, &ProcEntry)) {
		printf("\n\t[!] Process32FirstW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		for (int i = 0; i < BLACKLISTARRAY_SIZE; i++) {
			if (wcscmp(ProcEntry.szExeFile, g_BlackListedDebuggers[i]) == 0) {
				wprintf(L"\n\t[i] Found \"%s\" Of Pid : %d\n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
				bSTATE = TRUE;
				break; // breaking from the for loop
			}
		}

		if (bSTATE)
			break; // breaking from the do-while loop

	} while (Process32Next(hSnapShot, &ProcEntry));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	return bSTATE;
}



BOOL TimeTickCheck1() {

	DWORD	dwTime1 = NULL,
		dwTime2 = NULL;

	dwTime1 = GetTickCount64();

	/*

		//	tech 1 :
		if (IsDebuggerPresent()) {
		}
		//	tech 2 :
		if (IsDebuggerPresent2()) {
		}
		//	tech 3 :
		if (NtQIPDebuggerCheck()) {
		}
		//	tech 4 :
		if (HardwareBpCheck()) {
		}
		//	tech 5 :
		if (IsDebuggerPresent3()) {
		}
		//	tech 6 :
		if (BlackListedProcessesCheck()) {
		}


	*/

	dwTime2 = GetTickCount64();

	printf("\n\t[i] (dwTime2 - dwTime1) : %d \n", (dwTime2 - dwTime1));

	if ((dwTime2 - dwTime1) > 50) {
		return TRUE;
	}

	return FALSE;
}



//------------------------------------------------------------------------------------------------------------------------------------------

// https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter

BOOL TimeTickCheck2() {

	LARGE_INTEGER	Time1 = { 0 },
		Time2 = { 0 };

	if (!QueryPerformanceCounter(&Time1)) {
		printf("\n\t[!] QueryPerformanceCounter [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	/*

		//	tech 1 :
		if (IsDebuggerPresent()) {
		}
		//	tech 2 :
		if (IsDebuggerPresent2()) {
		}
		//	tech 3 :
		if (NtQIPDebuggerCheck()) {
		}
		//	tech 4 :
		if (HardwareBpCheck()) {
		}
		//	tech 5 :
		if (IsDebuggerPresent3()) {
		}
		//	tech 6 :
		if (BlackListedProcessesCheck()) {
		}
	*/


	if (!QueryPerformanceCounter(&Time2)) {
		printf("\n\t[!] QueryPerformanceCounter [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\n\t[i] (Time2.QuadPart - Time1.QuadPart) : %d \n", (Time2.QuadPart - Time1.QuadPart));

	if ((Time2.QuadPart - Time1.QuadPart) > 100000) {
		return TRUE;
	}

	return FALSE;
}


//------------------------------------------------------------------------------------------------------------------------------------------

// https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugbreak

BOOL DebugBreakCheck() {

	__try {
		DebugBreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		return FALSE;
	}

	return TRUE;
}




BOOL OutputDebugStringCheck() {

	SetLastError(1);
	OutputDebugStringW(L"MalDev Academy");

	if (GetLastError() == 0) {
		return TRUE;
	}

	return FALSE;
}




