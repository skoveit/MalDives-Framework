#pragma once
#include <../include/SysWhispers.h>

typedef struct _Syscall {

	fnNtAllocateVirtualMemory	pNtAllocateVirtualMemory;
	fnNtProtectVirtualMemory	pNtProtectVirtualMemory;
	fnNtWriteVirtualMemory		pNtWriteVirtualMemory;
	fnNtCreateThreadEx			pNtCreateThreadEx;

}Syscall, * PSyscall;


BOOL ClassicInjectionViaNTdll(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize);
BOOL MappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize);
BOOL ApcInjectionViaSyscalls(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pPayload, IN SIZE_T sPayloadSize);

VOID AlterableFunction();
