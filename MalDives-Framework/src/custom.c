#include <Windows.h>
#include "../include/custom.h"
#include "../include/customStruct.h"
#include "../include/crypt.h"

HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);

	PLIST_ENTRY				pListHead = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY				pListNode = (PLIST_ENTRY)pListHead->Flink;

	do
	{
		if (pDte->FullDllName.Length != NULL) {
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif 
			}

			pDte = (PLDR_DATA_TABLE_ENTRY)(pListNode->Flink);

			pListNode = (PLIST_ENTRY)pListNode->Flink;

		}
	} while (pListNode != pListHead);



	return NULL;
}
FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {
	PBYTE pBase = (PBYTE)hModule;
	
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	PVOID pFunctionAddress; 
	for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		if (strcmp(lpApiName, pFunctionName) == 0) {
			pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
			return pFunctionAddress;
		}
	}

	return NULL;
}

// ===========================
HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash) {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);

	PLIST_ENTRY				pListHead = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY				pListNode = (PLIST_ENTRY)pListHead->Flink;

	do
	{
		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {

			CHAR UpperCaseDllName[MAX_PATH];
			for (DWORD i = 0; i < pDte->FullDllName.Length; i++) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
			}
			UpperCaseDllName[pDte->FullDllName.Length] = '\0';

			if (HASHA(UpperCaseDllName) == dwModuleNameHash) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif 
			}

			pDte = (PLDR_DATA_TABLE_ENTRY)(pListNode->Flink);

			pListNode = (PLIST_ENTRY)pListNode->Flink;

		}
	} while (pListNode != pListHead);



	return NULL;
}
FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwAPINameHash) {
	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		if (HASHA(pFunctionName) == dwAPINameHash) {
			printf("[+] Found API \"%s\" \n", pFunctionName);
			PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
			return pFunctionAddress;
		}
	}

	return NULL;
}
