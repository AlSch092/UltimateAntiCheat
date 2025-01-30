//By AlSch092 @github
#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "../Common/Globals.hpp"
#include "../Common/Settings.hpp"
#include "../Network/HttpClient.hpp"
#include "NAuthenticode.hpp"

#include <Psapi.h>
#include <unordered_map>

using namespace std;

struct ModuleHashData //to avoid needing a `list<tuple<wstring,list<uint64>>>`  as ModuleHashes
{
	wchar_t* Name;
	vector<uint64_t> Hashes;
};

class Integrity final
{
public:

	Integrity(vector<ProcessData::MODULE_DATA>* startupModuleList) //modules gathered at program startup
	{
		WhitelistedModules = new vector<ProcessData::MODULE_DATA>();
		ModuleHashes = new vector< ModuleHashData*>();

		for (const ProcessData::MODULE_DATA& mod : *startupModuleList)
		{
			WhitelistedModules->push_back(mod);
		}

		ModuleHashes = GetModuleHashes(); 
	}

	~Integrity()
	{
		if(WhitelistedModules != nullptr)
			delete WhitelistedModules;

		if (ModuleHashes != nullptr)
		{
			for (std::vector<ModuleHashData*>::const_iterator it = ModuleHashes->begin(); it != ModuleHashes->end(); ++it)
			{
				if ((*it)->Name != nullptr)
					delete[](*it)->Name;

				delete* it;
			}
		}
	}

	bool Check(uint64_t Address, int nBytes, vector<uint64_t> hashList);
	
	static vector<uint64_t> GetMemoryHash(uint64_t Address, int nBytes);

	void SetSectionHashList(vector<uint64_t> hList, const string section);

	vector<uint64_t> GetSectionHashList(const string sectionName) const 
	{
		auto it = this->SectionHashes.find(sectionName);

		if (it != this->SectionHashes.end())
		{
			return it->second;
		}

		return {};
	}

	bool IsUnknownModulePresent(); //traverse loaded modules to find any unknown ones (not signed & not whitelisted, in particular)

	vector<ProcessData::MODULE_DATA>* GetWhitelistedModules() const { return this->WhitelistedModules; }
	
	void AddToWhitelist(ProcessData::MODULE_DATA mod) { if(this->WhitelistedModules != nullptr) WhitelistedModules->push_back(mod); }

	void AddModuleHash(vector<ModuleHashData*>* moduleHashList, wchar_t* moduleName);
	ModuleHashData* GetModuleHash(const wchar_t* moduleName);

	vector<ModuleHashData*>* GetModuleHashes();

	bool IsModuleModified(const wchar_t* moduleName); //pinpoint any specific modules that have had their .text sections changed

	bool IsTLSCallbackStructureModified() const; //checks the TLSCallback structure in data directory for mods

private:
	
	unordered_map<string, vector<uint64_t>> SectionHashes; //section hashes for current module's sections

	vector<ProcessData::MODULE_DATA>* WhitelistedModules = nullptr;
	vector<ModuleHashData*>* ModuleHashes = nullptr;

	const char* BlacklistedDriversRepository = "http://github.com/someUser/someBlacklistedDriverRepo"; //will be adding this in future code pushes - fetch blacklisted drivers from some cloud location
	const char* BlacklisteBytePatternRepository = "http://github.com/someUser/someBlacklistedBytePatternsRepo"; //will be adding this in future code pushes - fetch blacklisted byte signatures/patterns from some cloud location
};