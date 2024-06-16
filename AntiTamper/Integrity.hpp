//By AlSch092 @github
#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "NAuthenticode.hpp"
#include "../Common/Globals.hpp"
#include <list>
#include <string>
#include <Psapi.h>
#include <stdio.h>
#include <algorithm>

using namespace std;

class Integrity
{
public:

	bool Check(uint64_t Address, int nBytes, std::list<uint64_t> hashList);
	
	static list<uint64_t> GetMemoryHash(uint64_t Address, int nBytes);

	void SetMemoryHashList(std::list<uint64_t> hList);
	list<uint64_t> GetMemoryHashList() { return this->_MemorySectionHashes; }

	bool IsUnknownModulePresent();

	vector<ProcessData::MODULE_DATA>* GetWhitelistedModules() { return this->WhitelistedModules; }
	void AddToWhitelist(ProcessData::MODULE_DATA mod) { if(this->WhitelistedModules != nullptr) WhitelistedModules->push_back(mod); }

	Integrity(vector<ProcessData::MODULE_DATA>* startupModuleList)
	{
		WhitelistedModules = new vector<ProcessData::MODULE_DATA>();

		for (auto mod : *startupModuleList)
		{
			WhitelistedModules->push_back(mod);
		}
	}

	~Integrity()
	{
		delete WhitelistedModules;
	}

private:
	
	list<uint64_t> _MemorySectionHashes; 
	vector<ProcessData::MODULE_DATA>* WhitelistedModules;
};