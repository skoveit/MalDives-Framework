#pragma once
#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

// XOR ---------------------------------------------------------------
VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey);
VOID XorByiKeys(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey);
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize);

// RC4 ---------------------------------------------------------------
VOID Rc4My(IN PBYTE pPayload, IN SIZE_T sPayloadSize, IN PBYTE pKey, IN SIZE_T sKeySize);

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
	);

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);

// UUID ---------------------------------------------------------------
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize);
BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize);


// HASH ---------------------------------------------------------------
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String); 
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);


// Protected Key -------------------------------------------------------
BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey);
VOID GenerateProtectedKey(IN BYTE HintByte, IN SIZE_T sKey, OUT PBYTE* ppProtectedKey);
