//By AlSch092 @github
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

	if (Address == 0)
		return hashList;

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

/*
	IsUnknownModulePresent - compares current module list to one gathered at program startup, any delta modules are checked via WinVerifyTrust and added to our `WhitelistedModules` member
	return true if an unsigned module (besides current executable) was found
*/
bool Integrity::IsUnknownModulePresent()
{
	bool foundUnknown = false;

	vector<ProcessData::MODULE_DATA> currentModules = *Process::GetLoadedModules();
	list<ProcessData::MODULE_DATA> modulesToAdd;

	for (auto it = currentModules.begin(); it != currentModules.end(); ++it) 
	{
		bool found_whitelisted = false;

		for (auto it2 = this->WhitelistedModules->begin(); it2 != this->WhitelistedModules->end(); ++it2) //our whitelisted module list is initially populated inside the constructor with modules gathered at program startup
		{
			if (wcscmp(it->baseName, it2->baseName) == 0)
			{
				found_whitelisted = true;
			}
		}

		if (!found_whitelisted)
		{
			if (Authenticode::VerifyEmbeddedSignature(it->name)) //if file is signed and not yet on our whitelist, we can add it
			{
				ProcessData::MODULE_DATA mod = *Process::GetModuleInfo(it->baseName);
				modulesToAdd.push_back(mod);		
			}
			else
			{
				Logger::logfw("UltimateAnticheat.log", Detection, L"Unsigned module was found loaded in the process: %s\n", it->name);
				foundUnknown = true;
			}
		}
	}

	for (const ProcessData::MODULE_DATA mod : modulesToAdd) //add any signed modules to our whitelist
	{
		this->WhitelistedModules->push_back(mod);
	}

	return foundUnknown;
}