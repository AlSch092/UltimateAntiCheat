//By AlSch092 @github
#include "Integrity.hpp"

//returns false if any static memory is modified (assuming we pass in moduleBase and sizeOfModule.
bool Integrity::Check(uint64_t Address, int nBytes, vector<uint64_t> hashList)
{
	bool hashesMatch = true;

	vector<uint64_t> hashes = GetMemoryHash(Address, nBytes);

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

vector<uint64_t> Integrity::GetMemoryHash(uint64_t Address, int nBytes)
{
	std::vector<uint64_t> hashList;

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

void Integrity::SetMemoryHashList(vector<uint64_t> hList)
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

	for (auto it = currentModules.begin(); it != currentModules.end(); ++it)  //if an attacker signs their dll, they'll be able to get past this
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
			if (Authenticode::HasSignature(it->name)) //if file is signed and not yet on our whitelist, we can add it
			{
				ProcessData::MODULE_DATA mod = *Process::GetModuleInfo(it->baseName);
				modulesToAdd.push_back(mod);		
			}
			else
			{
				Logger::logfw("UltimateAnticheat.log", Detection, L"Unsigned module was found loaded in the process: %s", it->name);
				foundUnknown = true;
			}
		}
	}

	for (const ProcessData::MODULE_DATA& mod : modulesToAdd) //add any signed modules to our whitelist
	{
		this->WhitelistedModules->push_back(mod);
	}

	return foundUnknown;
}

/*
GetModuleHash - searches `ModuleHashes` variable for module with name `moduleName`
returns nullptr if not found
*/
ModuleHashData* Integrity::GetModuleHash(const wchar_t* moduleName)
{
	string modName = Utility::ConvertWStringToString(moduleName);
	list<ProcessData::Section*>* sections = Process::GetSections(modName);

	for (auto s : *sections)
	{
		if (strcmp(s->name, ".text") == 0)
		{
			uint64_t sec_addr = (uint64_t)(s->address) + (uint64_t)GetModuleHandleA(modName.c_str());
			vector<uint64_t> hashes = GetMemoryHash(sec_addr, s->size); //make hashes of .text of module

			ModuleHashData* moduleHashData = new ModuleHashData();
			int name_len = wcslen(moduleName);
			moduleHashData->Name = new wchar_t[name_len + 1];
			wcscpy(moduleHashData->Name, moduleName);
			moduleHashData->Hashes = hashes;

			return moduleHashData;
		}
	}

	return nullptr;
}

/*
	GetModuleHashes  - fill member `ModuleHashes` with hashes of each whitelisted module
*/
vector<ModuleHashData*>* Integrity::GetModuleHashes()
{
	vector<ModuleHashData*>* moduleHashes = new vector<ModuleHashData*>();

	for (auto it = this->WhitelistedModules->begin(); it != this->WhitelistedModules->end(); ++it) //traverse whitelisted modules
	{
		if (it->dllInfo.lpBaseOfDll == GetModuleHandleA(NULL)) //skip main executable module, we're tracking that with another member
			continue;

		AddModuleHash(moduleHashes, it->baseName);
	}

	return moduleHashes;
}

/*
	IsModuleModified - checks if module `moduleName` has had its .text section modified (compared to `ModuleHashes` member)
	returns true if current module hash does not match original from `ModuleHashes`
*/
bool Integrity::IsModuleModified(const wchar_t* moduleName)
{
	bool foundModified = false;

	ModuleHashData* currentModuleHash = GetModuleHash(moduleName);

	for (ModuleHashData* modHash : *this->ModuleHashes)
	{
		if (wcscmp(modHash->Name, currentModuleHash->Name) == 0) //moduleName matches module in list
		{
			if (modHash->Hashes.size() != currentModuleHash->Hashes.size()) //size check
			{
				delete[] currentModuleHash->Name;
				delete currentModuleHash; //return true if sizes dont match, attacker may have increased memory size at end of section to avoid detection (or they re-wrote entire dll's memory)
				return true;
			}

			uint64_t* arr1 = modHash->Hashes.data();
			size_t size = modHash->Hashes.size();

			uint64_t* arr2 = currentModuleHash->Hashes.data();

			for (int i = 0; i < size - 1; i++)
			{
				if (arr1[i] != arr2[i])
				{
					foundModified = true;
				}
			}

			break;
		}
	}

	delete[] currentModuleHash->Name;
	delete currentModuleHash;
	return foundModified;
}

/*
	AddModuleHash - fetches hash list for `moduleName` and adds to `moduleHashList`
*/
void Integrity::AddModuleHash(vector<ModuleHashData*>* moduleHashList, wchar_t* moduleName)
{
	if (moduleHashList == nullptr || moduleName == nullptr)
		return;

	string modName = Utility::ConvertWStringToString(moduleName);
	list<ProcessData::Section*>* sections = Process::GetSections(modName);

	for (auto s : *sections)
	{
		if (strcmp(s->name, ".text") == 0)
		{
			uint64_t sec_addr = (uint64_t)(s->address) + (uint64_t)GetModuleHandleA(modName.c_str());
			vector<uint64_t> hashes = GetMemoryHash(sec_addr, s->size); //make hashes of .text of module

			ModuleHashData* moduleHashData = new ModuleHashData();
			int name_len = wcslen(moduleName);
			moduleHashData->Name = new wchar_t[name_len + 1];
			wcscpy(moduleHashData->Name, moduleName);
			moduleHashData->Hashes = hashes;

			moduleHashList->push_back(moduleHashData);
			break;
		}
	}
}