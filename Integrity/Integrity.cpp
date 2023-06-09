#include "Integrity.hpp"

//Call chain: GetHash() to get a hash list of module, then later call Check with the result from GetHash originally.
//working! returns false if any static memory is modified (assuming we pass in moduleBase and sizeOfModule.
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

	for (int i = 0; i < nBytes; i = i + 32)
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
				// Print the module name and handle value.
				if(wcsstr(szModName, L".exe") == NULL)
					dlls.push_back(szModName);
			}
		}
	}

	return dlls;
}

list<uint64_t> Integrity::GetDllHashes(list<wchar_t*> LoadedDlls)
{
	list<uint64_t> dllHashes;


	return dllHashes;
}

bool Integrity::IsUnknownDllPresent()
{
	bool foundUnknown = false;

	list<wstring> dlls = Integrity::GetLoadedDLLs();

	for (auto str : dlls)
	{
		if (!Authenticode::VerifyEmbeddedSignature(str.c_str()))
		{
			wprintf(L"Bad signature found for: %s\n", str.c_str());
			foundUnknown = true;
		}
	}

	return foundUnknown;
}