#include "Integrity.hpp"

//Call chain: GetHash() to get a hash list of module, then later call Check with the result from GetHash originally.
//returns false if any static memory is modified (assuming we pass in moduleBase and sizeOfModule.
bool Integrity::Check(uint64_t Address, int nBytes, std::list<uint64_t>* hashList)
{
	list<uint64_t>* hashes = GetMemoryHash(Address, nBytes);

	bool b_perm = std::is_permutation(hashList->begin(), hashList->end(), hashes->begin()); //check if our ordered hash list is the same as the one we compute above

	delete hashes;

	return b_perm;
}

//we can build an array here at some memory location with nBytes, then SHA256 
list<uint64_t>* Integrity::GetMemoryHash(uint64_t Address, int nBytes)
{
	std::list<uint64_t>* hashList = new list<uint64_t>();

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
		hashList->push_back(digestCache);
		delete digest;
	}

	delete[] arr;
	return hashList;
}

void Integrity::SetMemoryHashList(std::list<uint64_t>* hList)
{
	if (this->_MemorySectionHashes == nullptr)
		this->_MemorySectionHashes = new list<uint64_t>();

	this->_MemorySectionHashes->assign(hList->begin(), hList->end());
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
		list<uint64_t>* dllHashes = Integrity::GetMemoryHash((uint64_t)GetModuleHandleW(dll), 0x1000);
		//HashesList->push_back(dllHashes[0]);
		delete dllHashes;
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

	if (!SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)2,
		&dynamicCodePolicy,
		sizeof(dynamicCodePolicy))) {
		fprintf(stderr, "Failed to set process mitigation policy. Error code: %lu\n", GetLastError());
		return false;
	}

	return true;
}

bool Integrity::DisableUnsignedCode() //stops unsigned dlls from being loaded! Gives 'Bad Image' error (0xc00000428)
{
	_PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signPolicy = { 0 };

	signPolicy.MicrosoftSignedOnly = true;

	if (!SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)8,
		&signPolicy,
		sizeof(signPolicy))) {
		fprintf(stderr, "Failed to set process mitigation policy. Error code: %lu\n", GetLastError());
		return false;
	}

	return true;
}