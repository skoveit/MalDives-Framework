#include <windows.h>
#include "../include/crypt.h"

#define INITIAL_SEED	7
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


// Protected Key -------------------------------------------------------

/*
	- HintByte : is the same hint byte that was used in the key generating function
	- pProtectedKey : the encrypted key
	- sKey : the key size
	- ppRealKey : pointer to a PBYTE buffer that will recieve the decrypted key
*/
BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {

	BYTE			b = 0;
	PBYTE			pRealKey = (PBYTE)malloc(sKey);

	if (!pRealKey)
		return NULL;

	while (1) {

		// using the hint byte, if this is equal, then we found the 'b' value needed to decrypt the key 
		if (((pProtectedKey[0] ^ b) - 0) == HintByte)
			break;
		// else, increment 'b' and try again
		else
			b++;
	}

	printf("[+] FOUND\n[+] Calculated Key Byte : 0x%0.2X \n", b);

	for (int i = 0; i < sKey; i++) {
		pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
	}


	*ppRealKey = pRealKey;

	return b;
}

/*
	- HintByte: is the hint byte that will be saved as the key's first byte
	- sKey: the size of the key to generate
	- ppProtectedKey: pointer to a PBYTE buffer that will recieve the encrypted key
*/
VOID GenerateProtectedKey(IN BYTE HintByte, IN SIZE_T sKey, OUT PBYTE* ppProtectedKey) {

	// genereting a seed
	srand(time(NULL));

	// 'b' is used as the key of the key encryption algorithm
	BYTE				b = rand() % 0xFF;
	// 'pKey' is where the original key will be generated to
	PBYTE				pKey = (PBYTE)malloc(sKey);
	// 'pProtectedKey' is the encrypted version of 'pKey' using 'b'
	PBYTE				pProtectedKey = (PBYTE)malloc(sKey);

	if (!pKey || !pProtectedKey)
		return;

	// genereting another seed
	srand(time(NULL) * 2);

	// the key starts with the hint byte
	pKey[0] = HintByte;
	// generating the rest of the key
	for (int i = 1; i < sKey; i++) {
		pKey[i] = (BYTE)rand() % 0xFF;
	}


	printf("[+] Generated Key Byte : 0x%0.2X \n\n", b);
	printf("[+] Original Key : ");

	// encrypting the key using a xor encryption algorithm
	// using 'b' as the key
	for (int i = 0; i < sKey; i++) {
		pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
	}

	// saving the encrypted key by pointer 
	*ppProtectedKey = pProtectedKey;

	// freeing the raw key buffer
	free(pKey);
}


