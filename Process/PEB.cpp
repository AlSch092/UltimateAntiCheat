#include "PEB.hpp"

#if IS_64_BIT
UINT64 GetPEBPointerAddress()
{
	typedef struct _TEB
	{
		PVOID Reserved1[12];
		PVOID ProcessEnvironmentBlock;
	} TEB, * PTEB;

	PTEB teb = (PTEB)__readgsqword(0x30);

	if (teb == NULL)
		return NULL;

	return (UINT64) & (teb->ProcessEnvironmentBlock);
}

PVOID GetPEBAddress()
{
	return (PVOID)__readgsqword(0x60);
}

void SetPEBAddress(UINT64 address)
{
	__try
	{
		UINT64 PEBPtrInTEB = GetPEBPointerAddress();
		*(UINT64*)PEBPtrInTEB = address;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Failed at SetPEBAddress: memory exception writing PEB ptr");
		return;
	}
}
#else

PVOID GetPEBAddress()
{
	PVOID pebAddress = 0;

	__asm
	{
		mov eax, fs: [0x18]
		mov eax, [eax + 0x30]
		mov pebAddress, eax
	}

	return pebAddress;
}

void SetPEBAddress(DWORD address)
{
	__asm
	{
		push ebx
		mov eax, fs: [0x18]
		mov eax, [eax + 0x30]
		mov ebx, address
		mov[eax], ebx
		pop ebx
	}
}

#endif

BYTE* CopyPEBBytes(unsigned int pebSize)
{
	LPVOID pebAddress = GetPEBAddress();

	int size_copy = sizeof(struct _MYPEB);
	BYTE* peb_bytes = new BYTE[size_copy];

	BOOL success = ReadProcessMemory(GetCurrentProcess(), pebAddress, peb_bytes, size_copy, NULL);
	if (!success)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Failed to copy PEB bytes. Error: %d\n", GetLastError());
		delete[] peb_bytes;
		return NULL;
	}

	return peb_bytes;
}

BYTE* CopyAndSetPEB()
{
	BYTE* newPeb = CopyPEBBytes(sizeof(struct _MYPEB)); //copy existing PEB into a byte array

	if (newPeb != NULL)
	{
		SetPEBAddress((UINT64)newPeb); //our byte array's address becomes the new PEB
	}
	else
	{
		Logger::logf("UltimateAnticheat.log", Err, "Failed to copy PEB bytes. Error: %d\n");
	}

	return newPeb;
}