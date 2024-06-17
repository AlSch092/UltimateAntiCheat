//By AlSch092 @github
#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "../Common/Globals.hpp"
#include "NAuthenticode.hpp"
#include <vector>
#include <string>
#include <Psapi.h>
#include <stdio.h>

using namespace std;

struct ModuleHashData //to avoid needing a `list<tuple<wstring,list<uint64>>>`  as ModuleHashes
{
	wchar_t* Name;
	vector<uint64_t> Hashes;
};

class Integrity
{
public:

	bool Check(uint64_t Address, int nBytes, vector<uint64_t> hashList);
	
	static vector<uint64_t> GetMemoryHash(uint64_t Address, int nBytes);

	void SetMemoryHashList(vector<uint64_t> hList);
	vector<uint64_t> GetMemoryHashList() { return this->_MemorySectionHashes; }

	bool IsUnknownModulePresent();

	vector<ProcessData::MODULE_DATA>* GetWhitelistedModules() { return this->WhitelistedModules; }
	void AddToWhitelist(ProcessData::MODULE_DATA mod) { if(this->WhitelistedModules != nullptr) WhitelistedModules->push_back(mod); }

	void AddModuleHash(vector<ModuleHashData*>* moduleHashList, wchar_t* moduleName);
	ModuleHashData* GetModuleHash(const wchar_t* moduleName);
	vector<ModuleHashData*>* GetModuleHashes();

	bool IsModuleModified(const wchar_t* moduleName); //pinpoint any specific modules that have had their .text sections changed

	Integrity(vector<ProcessData::MODULE_DATA>* startupModuleList) //modules gathered at program startup
	{
		WhitelistedModules = new vector<ProcessData::MODULE_DATA>();
		ModuleHashes = new vector< ModuleHashData*>();

		for (const ProcessData::MODULE_DATA mod : *startupModuleList)
		{
			WhitelistedModules->push_back(mod);
		}

		ModuleHashes = GetModuleHashes(); //
	}

	~Integrity()
	{
		delete WhitelistedModules;

		if (ModuleHashes != nullptr)
		{
			for (std::vector<ModuleHashData*>::const_iterator it = ModuleHashes->begin(); it != ModuleHashes->end(); ++it)
			{
				if ((*it)->Name != nullptr)
					delete[] (*it)->Name;

				delete *it;
			}
		}

	}

private:
	
	vector<uint64_t> _MemorySectionHashes; //hashes of .text section of executable module
	vector<ProcessData::MODULE_DATA>* WhitelistedModules = nullptr;

	vector<ModuleHashData*>* ModuleHashes = nullptr; //tuple of module name, and their list of hashes
};