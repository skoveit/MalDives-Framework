#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);


// PROCESS ENUM ========================================================================== 
BOOL PrintProcesses();
BOOL GetRemoteProcessHandleEnum(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess);
BOOL GetRemoteProcessHandleNt(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess);
BOOL GetRemoteProcessHandleSnapshot(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess);

// THREAD ENUM ========================================================================== 
BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread);
BOOL GetRemoteThreadhandle(IN DWORD dwProcessId, OUT DWORD* dwThreadId, OUT HANDLE* hThread);

// PROCESS INJECTION ========================================================================== 
BOOL InjectDllToRemoteProcess(HANDLE hProcess, LPWSTR DllName);
BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);
BOOL InjectShellcodeToLocalProcess(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);
BOOL DirectApcInjection(IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode);


// CREATE PROCESS =============================================================================
BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);
BOOL CreateSuspendedProcess2(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);
BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);
BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread);