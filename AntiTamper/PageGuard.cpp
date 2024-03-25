#include "PageGuard.hpp"

/*
Test to see if we can make some sort of read protected memory which contains actual values we can work with
*/
bool MakeGuardedMemory(UINT64 _address)
{
	LPVOID lpvAddr;               // address of the test memory
	DWORD dwPageSize;             // amount of memory to allocate.
	BOOL bLocked;                 // address of the guarded memory
	SYSTEM_INFO sSysInfo;         // useful information about the system

	GetSystemInfo(&sSysInfo);     // initialize the structure

	_tprintf(TEXT("This computer has page size %d.\n"), sSysInfo.dwPageSize);

	dwPageSize = sSysInfo.dwPageSize;

	// Try to allocate the memory.

	lpvAddr = VirtualAlloc(&_address, dwPageSize, //_address might not work, need to check
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READONLY | PAGE_GUARD);

	if (lpvAddr == NULL) {
		_tprintf(TEXT("VirtualAlloc failed. Error: %ld\n"),
			GetLastError());
		return 1;

	}
	else {
		_ftprintf(stderr, TEXT("Committed %lu bytes at address 0x%lp\n"),
			dwPageSize, lpvAddr);
	}

	printf("%llx\n", lpvAddr);
	//system("pause");

	DWORD a = 0;
	//memcpy((void*)&a, (void*)lpvAddr, 2);
	printf("%x\n", *(DWORD*)lpvAddr); //detect memory accesses! can we somehow add this into UAC?

	// Try to lock the committed memory. This fails the first time 
	// because of the guard page.

	bLocked = VirtualLock(lpvAddr, dwPageSize);
	if (!bLocked) {
		_ftprintf(stderr, TEXT("Cannot lock at %lp, error = 0x%lx\n"),
			lpvAddr, GetLastError());
	}
	else {
		_ftprintf(stderr, TEXT("Lock Achieved at %lp\n"), lpvAddr);
	}

	// Try to lock the committed memory again. This succeeds the second
	// time because the guard page status was removed by the first 
	// access attempt.

	bLocked = VirtualLock(lpvAddr, dwPageSize);

	if (!bLocked) {
		_ftprintf(stderr, TEXT("Cannot get 2nd lock at %lp, error = %lx\n"),
			lpvAddr, GetLastError());
	}
	else {
		_ftprintf(stderr, TEXT("2nd Lock Achieved at %lp\n"), lpvAddr);
	}

	system("pause");
	return 0;
}