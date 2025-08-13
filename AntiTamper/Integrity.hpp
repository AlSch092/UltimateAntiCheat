//By AlSch092 @github
#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "../Common/Settings.hpp"
#include "../Network/HttpClient.hpp"
#include "../Process/Process.hpp"
#include "NAuthenticode.hpp"

#include <Psapi.h>
#include <unordered_map>
#include <mutex>

using namespace std;

/**
 * @brief IntegrityViolation structure tracks anomalies with module integrity
 */
struct IntegrityViolation
{
public:
	enum Type
	{
		None = 0,
		Integrity,
		Debugging,
		License,
		CodeSignature,
	};

	Type type = Type::None;
	uintptr_t address = 0;
	std::wstring description;
	uint64_t timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

	std::wstring module;
	std::wstring section;

	IntegrityViolation(std::wstring _module, std::wstring _section, std::wstring _description, uintptr_t _address)
		: module(_module), section(_section)
	{
		this->description = _description;
		this->address = _address;
	}

	bool operator==(const IntegrityViolation& other) const noexcept
	{
		return module == other.module && section == other.section && address == other.address;
	}
};

/**
 * @brief ModuleChecksumData holds information about the checksums of each section of a module
 */
struct ModuleChecksumData
{
	HMODULE hMod = 0;
	std::wstring Name;
	std::wstring Path;
	std::unordered_map<std::string, uintptr_t> SectionChecksums; //stores checksums for each section in the module

	bool operator==(const ModuleChecksumData& other) const noexcept
	{
		return hMod == other.hMod && Name == other.Name && Path == other.Path;
	}
};

/**
 * @brief Class that deals with checksums and runtime integrity
 * @details Tracks changes to unwritable sections of all loaded modules, along with checking for abnormal writable pages
 * @details It also compares loaded modules to their files on disc
 */
class Integrity final
{
public:

	Integrity(Settings* s) : Config(s)
	{
		if (s == nullptr)
		{
			throw std::runtime_error("Null pointer error");
		}

		this->ModuleList = Process::GetLoadedModules(); //get the list of loaded modules at the time of instantiation

		if (this->ModuleList.empty())
		{
#ifdef _LOGGING_ENABLED
			Logger::logf(Err, "Failed to retrieve loaded modules during Integrity class instantiation");
#endif
			throw std::runtime_error("Failed to retrieve loaded modules during Integrity class instantiation");
		}

		for (auto module : ModuleList) //store hashes of all loaded modules for all non-writable sections
		{
			ModuleChecksumData moduleChecksum;
			moduleChecksum.hMod = module.hModule;
			moduleChecksum.Name = module.baseName;
			moduleChecksum.Path = module.nameWithPath;

			auto nonWritableSections = Process::FindNonWritableSections(Utility::ConvertWStringToString(module.baseName)); //.rdata is not a 'guaranteed' section name, especially on WoW64

			for (const auto& section : nonWritableSections)
			{
				uintptr_t checksum = Integrity::CalculateChecksumFromSection(Utility::ConvertWStringToString(module.baseName), section.name.c_str());
				moduleChecksum.SectionChecksums[section.name.c_str()] = checksum;

#ifdef _LOGGING_ENABLED	
				Logger::logf(Info, "Section %s checksum: %llx", section.name.c_str(), checksum);
#endif
			}

			StoreModuleChecksum(moduleChecksum); //tested and working fine
		}

		try
		{
			PeriodicIntegrityCheckThread = std::make_unique<Thread>((LPTHREAD_START_ROUTINE)&PeriodicIntegrityCheck, (LPVOID)this, true, false);
		}
		catch (const std::bad_alloc& ex)
		{
			throw std::runtime_error("Failed to create PeriodicIntegrityCheckThread: " + std::string(ex.what()));
		}
	}

	~Integrity()
	{
		if (PeriodicIntegrityCheckThread && PeriodicIntegrityCheckThread->IsThreadRunning(PeriodicIntegrityCheckThread->GetHandle()))
		{
			PeriodicIntegrityCheckThread->SignalShutdown(TRUE);
			PeriodicIntegrityCheckThread->JoinThread();
		}
	}

	Integrity& operator=(Integrity&& other) = delete; //delete move assignments
	Integrity operator+(Integrity& other) = delete; //delete all arithmetic operators, unnecessary for context
	Integrity operator-(Integrity& other) = delete;
	Integrity operator*(Integrity& other) = delete;
	Integrity operator/(Integrity& other) = delete;

	static uintptr_t FindWritableAddress(__in const std::string moduleName, __in const std::string sectionName);
	static bool IsReturnAddressInModule(__in const uintptr_t RetAddr, __in const wchar_t* module);

	static uintptr_t CalculateChecksumFromSection(const std::string module, const char* sectionName);

	static bool CompareChecksum(__in const std::string module, __in const char* section, __in const uintptr_t previous_checksum);
	static bool CompareChecksumToFileOnDisc(__in const std::wstring& module, __in const char* section, __in const uintptr_t previous_checksum);

	static uintptr_t GetSectionChecksumFromDisc(__in const std::wstring path, __in const char* sectionName);

	bool CheckLoadedModuleHashVersusDiskHash(__in const std::string module, __in const char* sectionName, __in std::wstring diskFilePath);

	static std::list<ProcessData::ImportFunction> FetchHookedIATEntries();
	static bool DoesIATContainHooked();

	static bool IsAddressInModule(__in const std::vector<ProcessData::MODULE_DATA>& modules, __in const uintptr_t address);
	static bool IsPEHeader(__in unsigned char* pMemory);

	static bool IsTLSCallbackStructureModified();

	void StoreModuleChecksum(ModuleChecksumData module)
	{
		auto it = std::find_if(this->ModuleChecksums.begin(), this->ModuleChecksums.end(), [module](const ModuleChecksumData& m) { return (module.hMod == m.hMod); });

		if (it == this->ModuleChecksums.end())
		{
			this->ModuleChecksums.push_back(module);
		}
	}

	uintptr_t RetrieveModuleChecksum(__in const HMODULE hMod, __in const char* section) const
	{
		auto it = std::find_if(this->ModuleChecksums.begin(), this->ModuleChecksums.end(), [hMod](const ModuleChecksumData& m) { return (hMod == m.hMod); });

		if (it == this->ModuleChecksums.end())
		{
			return 0;
		}

		return it->SectionChecksums.at(std::string(section));
	}

	auto GetViolations() const noexcept
	{
		std::lock_guard<std::mutex> lock(ViolationsMutex);
		return this->Violations;
	}

	void AddViolation(const IntegrityViolation& iv)
	{
		std::lock_guard<std::mutex>  lock(ViolationsMutex);
		if (std::find(Violations.begin(), Violations.end(), iv) == Violations.end())
			Violations.push_back(iv);
	}

	mutable std::mutex ViolationsMutex;

private:

	std::vector<ProcessData::MODULE_DATA> ModuleList;

	std::vector<ModuleChecksumData> ModuleChecksums; //stores module checksums for quick access

	std::unique_ptr<Thread> PeriodicIntegrityCheckThread = nullptr; //thread for periodic integrity checks

	static void PeriodicIntegrityCheck(LPVOID thisClassPtr); //performs periodic integrity checks on the process and its modules

	Settings* Config = nullptr; //non-owning pointer; do not delete at class destruction. 

	std::vector<IntegrityViolation> Violations;

};