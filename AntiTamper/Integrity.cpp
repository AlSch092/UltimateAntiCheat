#include "Integrity.hpp"

//returns false if any static memory is modified (assuming we pass in moduleBase and sizeOfModule.
bool Integrity::Check(uint64_t Address, int nBytes, std::list<uint64_t> hashList)
{
	bool hashesMatch = true;

	list<uint64_t> hashes = GetMemoryHash(Address, nBytes);

	auto it1 = hashes.begin();
	auto it2 = hashList.begin();

	while (it1 != hashes.end() && it2 != hashList.end())  //iterate both lists at same time, compare each element
	{
		if (it1 == hashes.end())
			break;

		if (*it1 != *it2)
		{
			hashesMatch = false;
			break;
		}

		++it1;		++it2;
	}

	return hashesMatch;
}

//we can build an array here at some memory location with nBytes, then SHA256 
list<uint64_t> Integrity::GetMemoryHash(uint64_t Address, int nBytes)
{
	std::list<uint64_t> hashList;

	byte* arr = new byte[nBytes];

	memcpy(arr, (void*)Address, nBytes);

	SHA256 sha;
	uint8_t* digest = 0;
	UINT64 digestCache = 0; //we keep adding 

	for (int i = 0; i < nBytes; i = i + 32) //as long as input->output matches consistently and does not create collisions, the underlying algo doesn't matter too much. 
	{
		sha.update(&arr[i], 32);
		digest = sha.digest();
		digestCache += *(UINT64*)digest + i;
		hashList.push_back(digestCache);
		delete digest;
	}

	delete[] arr;
	return hashList;
}

void Integrity::SetMemoryHashList(std::list<uint64_t> hList)
{
	this->_MemorySectionHashes.assign(hList.begin(), hList.end());
}

list<wstring> Integrity::GetLoadedDLLs()
{
	list<wstring> dlls;
	HMODULE  hMod[1024] = { 0 };
	DWORD cbNeeded;

	if (EnumProcessModules(GetCurrentProcess(), hMod, sizeof(hMod), &cbNeeded))
	{
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameExW(GetCurrentProcess(), hMod[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				//if(wcsstr(szModName, L".exe") == NULL) //skips .exe, adds everything else
				dlls.push_back(szModName);
			}
		}
	}

	return dlls;
}
/*
In addition to authenticode, we can make hashes of all the loaded DLLs and then periodically check these hashes again to see if any modifications have been made/modules hijacked
*/
list<uint64_t>* Integrity::GetDllHashes(list<wchar_t*> LoadedDlls)
{
	list<uint64_t>* HashesList = NULL;

	for (auto dll : LoadedDlls)
	{
		list<uint64_t> dllHashes = Integrity::GetMemoryHash((uint64_t)GetModuleHandleW(dll), 0x1000);
		//HashesList->push_back(dllHashes[0]);
	}
	
	return HashesList; //todo: finish this routine
}

/*
Authenticode check on loaded DLLs, any unsigned/unverified loaded returns true
*/
bool Integrity::IsUnknownDllPresent()
{
	bool foundUnknown = false;

	list<wstring> dlls = Integrity::GetLoadedDLLs();

	for (auto str : dlls)
	{
		//check dll name against a pre-determined white-list of DLLs

		if (!Authenticode::VerifyEmbeddedSignature(str.c_str()))
		{
			wprintf(L"Bad signature or no signature found for: %s\n", str.c_str());
			foundUnknown = true;
		}
	}

	return foundUnknown;
}

bool Integrity::DisableDynamicCode()
{
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = { 0 };

	dynamicCodePolicy.ProhibitDynamicCode = 1; // Enable dynamic code restriction

	if (!SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)2, &dynamicCodePolicy, sizeof(dynamicCodePolicy))) 
	{ 
		fprintf(stderr, "Failed to set process mitigation policy. Error code: %lu\n", GetLastError());
		return false;
	}

	return true;
}

bool Integrity::DisableUnsignedCode() //stop some unsigned dlls from being loaded
{
	_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signPolicy = { 0 };

	signPolicy.MicrosoftSignedOnly = true;

	if (!SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)8, &signPolicy, sizeof(signPolicy)))
	{
		fprintf(stderr, "Failed to set process mitigation policy. Error code: %lu\n", GetLastError());
		return false;
	}

	return true;
}

bool Integrity::IsFunctionHooked(const char* module, const char* name) //check for jmp's on the first byte of a function, best used on WINAPI
{


	return false;
}