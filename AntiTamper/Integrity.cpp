//By AlSch092 @github
#include "Integrity.hpp"

/*
    Integrity::Check - fetches list of hashes from .text section and compares to `hashList`
	returns `true` if hash lists match
*/
bool Integrity::Check(__in uint64_t Address, __in int nBytes, __in vector<uint64_t> hashList)
{
	bool hashesMatch = true;

	vector<uint64_t> hashes = GetMemoryHash(Address, nBytes);

	for (int i = 0; i < hashes.size() - 1; i++)
	{
		if (hashes[i] != hashList[i])
		{
			hashesMatch = false;
			break;
		}
	}

	return hashesMatch;
}

vector<uint64_t> Integrity::GetMemoryHash(__in uint64_t Address, __in int nBytes)
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

void Integrity::SetSectionHashList(__out vector<uint64_t> hList, __in const string section)
{
	this->SectionHashes[section].assign(hList.begin(), hList.end());
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
				break;
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
	GetModuleHash - fetches .text section hashes for a specific module,
     returns a `ModuleHashData` object, returns nullptr if module or section not found
*/
ModuleHashData* Integrity::GetModuleHash(__in const wchar_t* moduleName)
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
			moduleHashData->Name = moduleName;
			moduleHashData->Hashes = hashes;

			return moduleHashData;
		}
	}

	return nullptr;
}

/*
	GetModuleHashes  - fill member `ModuleHashes` with hashes of each whitelisted module's .text section
	returns a vector* of `ModuleHashData*` objects
*/
vector<ModuleHashData*>* Integrity::GetModuleHashes()
{
	vector<ModuleHashData*>* moduleHashes = new vector<ModuleHashData*>();

	for (auto it = this->WhitelistedModules->begin(); it != this->WhitelistedModules->end(); ++it) //traverse whitelisted modules
	{
		if (it->dllInfo.lpBaseOfDll == GetModuleHandleA(NULL)) //skip main executable module, we're tracking that with another member. they could probably be merged into one list to optimize
			continue;

		AddModuleHash(moduleHashes, it->baseName);
	}

	return moduleHashes;
}

/*
	IsModuleModified - checks if module `moduleName` has had its .text section modified (compared to `ModuleHashes` member)
	returns true if current module hash does not match original from `ModuleHashes`
*/
bool Integrity::IsModuleModified(__in const wchar_t* moduleName)
{
	bool foundModified = false;

	ModuleHashData* currentModuleHash = GetModuleHash(moduleName);

	for (ModuleHashData* modHash : *this->ModuleHashes)
	{
		if (modHash->Name == currentModuleHash->Name) //moduleName matches module in list
		{
			if (modHash->Hashes.size() != currentModuleHash->Hashes.size()) //size check
			{
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
					break; //break out of checker loop
				}
			}

			if (foundModified) //break out of outer loop
				break;
		}
	}

	delete currentModuleHash;
	return foundModified;
}

/*
	AddModuleHash - fetches hash list for `moduleName` and adds to `moduleHashList`
*/
void Integrity::AddModuleHash(__in vector<ModuleHashData*>* moduleHashList, __in wchar_t* moduleName)
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
			moduleHashData->Name = moduleName;
			moduleHashData->Hashes = hashes;

			moduleHashList->push_back(moduleHashData);
			break;
		}
	}
}

/*
	Integrity::IsTLSCallbackModified() - checks if the pointer to the TLS callback address has been modified
	Note: Someone should only be able to modifyh th
*/
bool Integrity::IsTLSCallbackStructureModified() const
{
	HMODULE hModule = GetModuleHandle(NULL);
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);

	IMAGE_TLS_DIRECTORY* tlsDir = (IMAGE_TLS_DIRECTORY*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress); //.data section

	HMODULE MainModule = GetModuleHandleA(NULL);
	UINT32 ModuleSize = Process::GetModuleSize(MainModule);

	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0) 
	{
		return true; //No TLS callbacks in data directory indicates something is wrong, abort!
	}

	if ((UINT64)tlsDir < (UINT64)MainModule || (UINT64)tlsDir > (UINT64)((UINT64)MainModule + ModuleSize)) //check if TLS directory address is inside main module for good measure
	{
		return true;
	}

	PIMAGE_TLS_CALLBACK* pTLSCallbacks = (PIMAGE_TLS_CALLBACK*)tlsDir->AddressOfCallBacks;

	int tlsCount = 0;

	for (int i = 0; pTLSCallbacks[i] != nullptr; i++) //traverse actual callback list, we are expecting (atleast) one callback in our program
	{
		if (!pTLSCallbacks)
			return true;

		if ((UINT64)pTLSCallbacks[i] < (UINT64)MainModule || (UINT64)pTLSCallbacks[i] > (UINT64)((UINT64)MainModule + ModuleSize)) //check if TLS callback is outside of main module range
		{
			return true;
		}

		tlsCount++;
	}

	if (tlsCount != 1) //last check to make sure there is atleast one TLS callback **note: you may have to modify this line if your protected program is using its own additional TLS callback**
		return true;  //an attacker may try to register their own additional TLS callback at runtime without changing the original one

	return false;
}

bool Integrity::IsPEHeader(__in unsigned char* pMemory)
{
	__try
	{
		if (*((WORD*)pMemory) != IMAGE_DOS_SIGNATURE) //check for "MZ" at the start
			return false;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pMemory;
	IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pMemory + pDosHeader->e_lfanew);

	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) //check for "PE" signature
		return false;

	return true;
}

/*
	IsAddressInModule - check if `address` falls within a known module (element of `modules`)
	returns `true` if `address` falls within a known module (element of `modules`)
*/
bool Integrity::IsAddressInModule(const std::vector<ProcessData::MODULE_DATA>& modules, uintptr_t address)
{
	for (const auto& module : modules)
	{
		if (address >= (DWORD_PTR)module.hModule && address < ((DWORD_PTR)module.hModule + module.dllInfo.SizeOfImage))
		{
			return true; // Address is within a known module
		}
	}
	return false;
}
