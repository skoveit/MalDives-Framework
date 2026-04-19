#include <windows.h>
#include <crypt.h>
#include <debug.h>

int main() {


	PBYTE pProtectedKey = NULL;
	PBYTE pRealKey = NULL;
	BYTE KEYSIZE = 0x22;
	
	GenerateProtectedKey(0xBA, KEYSIZE, &pProtectedKey);
	PrintHexData("First", pProtectedKey, KEYSIZE);

	if (!BruteForceDecryption(0xBA, pProtectedKey, KEYSIZE, &pRealKey)) {
		printf("[!] FAILED \n");
		return -1;
	}

	if (!BruteForceDecryption(0xBA, pProtectedKey, KEYSIZE, &pRealKey)) {
		printf("[!] FAILED \n");
		return -1;
	}

	PrintHexData("Second", pRealKey, KEYSIZE);
	
	free(pProtectedKey);
	free(pRealKey);

	return 0;
}