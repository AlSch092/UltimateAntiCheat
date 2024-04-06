#include "Integrity.hpp"

//returns false if any static memory is modified (assuming we pass in moduleBase and sizeOfModule.
bool Integrity::Check(uint64_t Address, int nBytes, std::list<uint64_t> hashList)
{
	bool hashesMatch = true;

	list<uint64_t> hashes = GetMemoryHash(Address, nBytes);

	auto it1 = hashes.begin();
	auto it2 = hashList.begin();

	int count = 0;

	while (it1 != hashes.end() && it2 != hashList.end())  //iterate both lists at same time, compare each element
	{
		if (count == hashes.size() - 1) //stop edge case error
			break;

		if (*it1 != *it2)
		{
			hashesMatch = false;
			break;
		}

		count++;
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
	UINT64 digestCache = 0;

	for (int i = 0; i < nBytes; i = i + 32)
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

list<wstring> Integrity::GetLoadedModules()
{
	list<wstring> modules;
	HMODULE  hMod[1024] = { 0 };
	DWORD cbNeeded;

	if (EnumProcessModules(GetCurrentProcess(), hMod, sizeof(hMod), &cbNeeded))
	{
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameExW(GetCurrentProcess(), hMod[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				modules.push_back(szModName);
			}
		}
	}

	return modules;
}

/*
Authenticode check on loaded DLLs, any unsigned/unverified loaded returns true
*/
bool Integrity::IsUnknownModulePresent()
{
	bool foundUnknown = false;

	list<wstring> modules = Integrity::GetLoadedModules();

	for (auto str : modules)
	{
		bool found_whitelisted = false;

		for (auto whitelist : WhitelistedModules)  //str is full path while whitelist is just name
		{
			if (wcsstr(str.c_str(), whitelist.c_str()) != NULL) //WARNING! wcsstr is not safe against overflows
			{
				found_whitelisted = true;
			}
		}

		if (!found_whitelisted)
		{
			//check dll name against a pre-determined white-list of DLLs, check if signed too
			if (!Authenticode::VerifyEmbeddedSignature(str.c_str()))
			{
				wprintf(L"Bad signature or no signature found for: %s\n", str.c_str());
				foundUnknown = true;
			}
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