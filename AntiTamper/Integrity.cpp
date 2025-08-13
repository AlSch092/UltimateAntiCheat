//By AlSch092 @github
#include "Integrity.hpp"

/**
 * @brief Calculates the checksum of a section of a module
 *
 * This function computes the checksum of a given
 * module, in its .text and .rdata sections
 *
 * @param `hMod` The module's base/start address in memory
 * @param `section` Section to create checksum from
 * @param `checksum` Previous computed checksum of hMod
 *
 * @return true/false if newly computed checksum equals `checksum` param
 *
 * @details If return false, the module has been modified or tampered with
 *
 *  @example DRM.cpp
 *
 * @usage
 * bool isModified = Integrity::CompareChecksum("DRMTest.exe", ".text", 12345678);
 */
bool Integrity::CompareChecksum(__in const std::string module, __in const char* section, __in const uintptr_t checksum)
{
	return (CalculateChecksumFromSection(module, section) == checksum);
}

/**
 * @brief Calculates the checksum of `module` disc file, compares it to `loadedImageChecksum`
 *
 * @details Used to check if file on disc matches its loaded image
 *
 * @param `hMod` The module's base/start address in memory
 * @param `section` Section to create checksum from
 * @param `loadedImageChecksum` Previous computed checksum of hMod
 *
 * @return true/false if newly computed checksum equals `checksum` param
 *
 * @details If return false, the module has been modified or tampered with
 *
 *  @example DRM.cpp
 *
 * @usage
 * bool isModified = Integrity::CompareChecksumToFileOnDisc("DRMTest.exe", ".text", 12345678);
 */
bool Integrity::CompareChecksumToFileOnDisc(__in const std::wstring& filePath, __in const char* section, __in const uintptr_t loadedImageChecksum)
{
	return (GetSectionChecksumFromDisc(filePath, section) == loadedImageChecksum);
}

/**
 * @brief Thread routine for periodic integrity checks
 *
 * This function computes the checksum of modules and compares it to
 * the checksums grabbed at program startup. Runs continuously
 *
 * @param classThisPtr Pointer to an Integrity class object
 *
 * @return No return value
 *
 * @details if checksums don't match, throws std::runtime_error
 *
 *  @example
 *
 * @usage
 * PeriodicIntegrityCheckThread = std::make_unique<Thread>(PeriodicIntegrityCheck, nullptr, true, false);
 */
void Integrity::PeriodicIntegrityCheck(LPVOID classThisPtr)
{
	if (classThisPtr == nullptr)
	{
		Logger::logfw(Err, L"PeriodicIntegrityCheck called with null class Ptr");
		throw std::runtime_error("PeriodicIntegrityCheck called with null class Ptr");
	}

	std::this_thread::sleep_for(std::chrono::seconds(3)); //wait a few seconds before starting the checks

	Integrity* integrity = reinterpret_cast<Integrity*>(classThisPtr);

	bool checking = true;

	std::string processName = Utility::ConvertWStringToString(Process::GetProcessName(GetCurrentProcessId()));

	HMODULE currentModule = GetModuleHandleA(processName.c_str());

	if (currentModule == NULL)
	{
		Logger::logfw(Err, L"Failed to get module handle for %s in PeriodicIntegrityCheck", processName.c_str());
		throw std::runtime_error("Failed to get module handle for current process in PeriodicIntegrityCheck");
	}

	while (checking)
	{
		uintptr_t checksum_main = 0;
		uintptr_t prev_checksum = 0;

		auto hookedIATEntries = FetchHookedIATEntries(); //this should go in a future or thread, has O(n^2) execution time where n=number loaded modules

		if (hookedIATEntries.size() > 0)
		{
			Logger::logfw(Detection, L"IAT was hooked!");

			for (const auto& hookedIATEntry : hookedIATEntries)
			{
				IntegrityViolation IV(Utility::ConvertStringToWString(hookedIATEntries.front().AssociatedModuleName), L".rdata", L"IAT Hooked", hookedIATEntry.AddressToFuncPtr);
				integrity->AddViolation(IV); //will avoid duplicates
			}
		}

		for (const auto& mod : integrity->ModuleChecksums) //check checksums of all loaded modules vs. what was gathered at startup
		{
			auto nonWritableSections = Process::FindNonWritableSections(Utility::ConvertWStringToString(mod.Name)); //.rdata is not a 'guaranteed' section name, especially on WoW64

			for (const auto& section : nonWritableSections)
			{
				HMODULE hMod = GetModuleHandleW(mod.Name.c_str());

				if (hMod == NULL) //this shouldn't happen unless possibly a module is unloaded 
				{
					Logger::logfw(Warning, L"Module %s was no longer found @ PeriodicIntegrityCheck", mod.Name.c_str());
					continue;
				}

				prev_checksum = integrity->RetrieveModuleChecksum(hMod, section.name.c_str()); //fetch old, don't calculate 

				if (!CompareChecksum(Utility::ConvertWStringToString(mod.Name), section.name.c_str(), prev_checksum))
				{

					Logger::logf(Detection, "Checksum for module %s, section %s is different, tampering detected", Utility::ConvertWStringToString(mod.Name).c_str(), section.name.c_str());
					IntegrityViolation IV(mod.Name, Utility::ConvertStringToWString(section.name), L"", (uintptr_t)mod.hMod + section.address);
					integrity->AddViolation(IV);				
				}

				if (!CompareChecksumToFileOnDisc(mod.Path, section.name.c_str(), CalculateChecksumFromSection(Utility::ConvertWStringToString(mod.Name), section.name.c_str())))
				{

					Logger::logf(Detection, "Checksum for module %s on disk (section %s) is different, tampering detected", Utility::ConvertWStringToString(mod.Name).c_str(), section.name.c_str());
					IntegrityViolation IV(mod.Name, Utility::ConvertStringToWString(section.name), L"", (uintptr_t)mod.hMod + section.address);
					integrity->AddViolation(IV);
					
				}

#ifndef _DEBUG
				if (uintptr_t addr = FindWritableAddress(Utility::ConvertWStringToString(mod.Name), section.name.c_str()) != 0) //check if any page is writable inside .text|.rdata
				{

					Logger::logf(Detection, "non-writable section %s had writable page at %llx", section.name.c_str(), addr);
#endif			

					IntegrityViolation IV(mod.Name, Utility::ConvertStringToWString(section.name), L"page=writable", (uintptr_t)mod.hMod + section.address);
					integrity->AddViolation(IV);
					
				}
			}
		}

		this_thread::sleep_for(std::chrono::seconds(5));
	}
}


/**
* @brief Reads a section of a file from disk and computes its hash
*
 * @param `path`  path to the file on disk
 *
 * @param `sectionName`  name of the section to read (e.g., ".text")
 *
 * @return uintptr_t checksum representing the .text section of the file
 *
 * @details This function reads the specified section from a PE file on disk and computes its hash.
 */
uintptr_t Integrity::GetSectionChecksumFromDisc(__in const std::wstring path, __in const char* sectionName)
{
	std::vector<uint8_t> sectionBytes;

	std::ifstream file(path, std::ios::binary);
	if (!file)
	{
		Logger::logfw(Detection, L"Error reading file: %s @ GetSectionHashFromDisc", path.c_str());
		return 0;
	}

	IMAGE_DOS_HEADER dosHeader;
	file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{

		Logger::logfw(Detection, L"Lacking MZ signature in file: %s @ GetSectionHashFromDisc", path.c_str());
		return 0;
	}

	file.seekg(dosHeader.e_lfanew, std::ios::beg);
	IMAGE_NT_HEADERS ntHeaders;
	file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
		Logger::logfw(Detection, L"Invalid PE signature in file: %s @ GetSectionHashFromDisc", path.c_str());
		return 0;
	}

	IMAGE_SECTION_HEADER sectionHeader;
	bool found = false;

	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER));
		if (strcmp((const char*)sectionHeader.Name, sectionName) == 0)
		{
			found = true;
			break;
		}
	}

	if (!found)
	{

		Logger::logfw(Detection, L"section not found in file: %s @ GetSectionHashFromDisc", path.c_str());
		return 0;
	}

	sectionBytes.resize(sectionHeader.SizeOfRawData);
	file.seekg(sectionHeader.PointerToRawData, std::ios::beg);
	file.read(reinterpret_cast<char*>(sectionBytes.data()), sectionHeader.SizeOfRawData);

	BYTE* sectionMemory = new BYTE[sectionHeader.SizeOfRawData];
	memcpy(sectionMemory, sectionBytes.data(), sectionHeader.SizeOfRawData);

	std::wstring processName = path.substr(path.find_last_of(L"\\") + 1);

	HMODULE hMod = GetModuleHandleW(processName.c_str());

	if (!hMod)
	{
		Logger::logfw(Detection, L"Failed to get module handle for %s @ GetSectionChecksumFromDisc", processName.c_str());
		return 0;
	}

	uintptr_t sectionChecksum = CalculateChecksumFromSection(Utility::ConvertWStringToString(processName), sectionName);

	if (sectionMemory != nullptr)
		delete[] sectionMemory;

	return sectionChecksum;
}

/**
 * @brief Calculates the checksum of a specific section in a module
 *
 * This function computes the checksum of a given section in a module.
 *
 * @param hMod The module's base/start address in memory
 * @param sectionName The name of the section to calculate the checksum for
 *
 * @return The sum of all bytes in the specified section
 *
 * @details N/A
 *
 * @usage
 * const uintptr_t result = Integrity::CalculateChecksumFromSection(GetModuleHandleA(NULL), ".text");
 */
uintptr_t Integrity::CalculateChecksumFromSection(const std::string module, const char* sectionName)
{
	if (module.empty() || sectionName == nullptr)
		return 0;

	uintptr_t checksum = 0;

	HMODULE hMod = GetModuleHandleA(module.c_str());

	if (hMod == NULL)
	{
		Logger::logfw(Err, L"Failed to get module handle for %s @ Integrity::CalculateChecksumFromSection", module.c_str());
		return 0;
	}

	auto SectionList = Process::GetSections(module);

	for (auto section : SectionList)
	{
		if (section.name == std::string(sectionName))
		{
			if (section.size > 0)
			{
				uintptr_t sectionChecksum = 0;

				uintptr_t sectionAddr = (uintptr_t)(section.address) + (uintptr_t)hMod;

				for (DWORD j = 0; j < section.size; j++)
					checksum += *(uint8_t*)(sectionAddr + j);

				break;
			}
		}
	}

	return checksum;
}

/**
 * @brief Checks if the loaded module's section hash matches the disk file's section hash
 *
 * This function compares the checksum of a specific section in a loaded module
 * with the checksum of the same section in a file on disk.
 *
 * @param hMod The handle to the loaded module
 * @param sectionName The name of the section to check
 * @param diskFilePath The path to the file on disk
 *
 * @return true if the checksums match, false otherwise
 *
 * @details N/A
 *
 * @usage
 * bool isValid = Integrity::CheckLoadedModuleHashVersusDiskHash(hMod, ".text", L"C:\\path\\to\\file.exe");
 */
bool Integrity::CheckLoadedModuleHashVersusDiskHash(__in const std::string module, __in const char* sectionName, __in std::wstring diskFilePath)
{
	if (module.empty() || sectionName == nullptr || diskFilePath.empty())
		return false;

	uintptr_t diskFileSectionChecksum = GetSectionChecksumFromDisc(diskFilePath, sectionName);
	uintptr_t loadedModuleSectionChecksum = CalculateChecksumFromSection(module, sectionName);

	return (diskFileSectionChecksum == loadedModuleSectionChecksum);
}

/**
 * @brief Finds a writable address in a specific section of a module
 *
 * This function searches for a writable address in the specified section of a module.
 *
 * @param moduleName The name of the module to search in
 * @param sectionName The name of the section to search in
 *
 * @return The address of the writable section, or 0 if not found
 *
 * @details N/A
 *
 * @usage
 * uintptr_t writableAddress = Integrity::FindWritableAddress("myModule.dll", ".rdata");
 */
uintptr_t Integrity::FindWritableAddress(__in const std::string moduleName, __in const std::string sectionName)
{
	if (moduleName.empty() || sectionName.empty())
	{
		return 0;
	}

	HMODULE hMod = GetModuleHandleA(moduleName.c_str());

	if (hMod == NULL)
	{
		Logger::logfw(Err, L"Failed to get module handle for %s @ Integrity::FindWritableAddress", moduleName.c_str());
		return 0;
	}

	const uintptr_t sectionAddr = Process::GetSectionAddress(hMod, sectionName.c_str());
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T result = 0;
	uintptr_t currentPageAddress = sectionAddr;

	const int pageSize = 0x1000;

	if (sectionAddr == NULL)
	{
		Logger::logf(Err, "section address was NULL @ Integrity::FindWritableAddress");
		return 0;
	}

	uintptr_t max_addr = sectionAddr + Process::GetSectionSize(hMod, sectionName);

	while ((result = VirtualQuery((LPCVOID)currentPageAddress, &mbi, sizeof(mbi))) != 0)     //Loop through all pages in .text
	{
		if (currentPageAddress >= max_addr)
			break;

		if (sectionName == ".text")
		{
			if (mbi.Protect != PAGE_EXECUTE_READ)
			{
				return currentPageAddress;
			}
		}
		else if (sectionName == ".rdata")
		{
			if (mbi.Protect != PAGE_READONLY)
			{
				return currentPageAddress;
			}
		}

		currentPageAddress += pageSize;
	}

	return 0;
}

/**
 * @brief Checks if an address `RetAddr` belongs to `module`'s .text section
 *
 *
 * @param `RetAddr` Address to check
 * @param `module` The name of the module to search in.
 *
 * @return True/False if `RetAddr` was located in `module`'s .text section
 *
 * @details  Passing a nullptr `module` results in `GetModuleHandleW(NULL)`, rather than an error
 *
 * @usage
 * if(IsReturnAddressInModule(*(uintptr_t*)_AddressOfReturnAddress(), "mydll.dll"))
 */
bool Integrity::IsReturnAddressInModule(__in const uintptr_t RetAddr, __in const wchar_t* module)
{
	if (RetAddr == 0)
	{
		Logger::logf(Err, "RetAddr was 0 @ : Integrity::IsReturnAddressInModule");
		return false;
	}

	HMODULE retBase = 0;

	if (module == nullptr)
		retBase = (HMODULE)GetModuleHandleW(NULL);
	else
		retBase = (HMODULE)GetModuleHandleW(module);

	if (retBase == 0)
	{
		Logger::logf(Err, "retBase was 0 @ : Integrity::IsReturnAddressInModule");
		return false;
	}

	DWORD size = Process::GetModuleSize(retBase);

	if (size == 0)
	{
		Logger::logf(Err, "size was 0 @ : Integrity::IsReturnAddressInModule");
		return false;
	}

	return (RetAddr >= (uintptr_t)retBase && RetAddr < ((uintptr_t)retBase + size)) ? true : false;
}

/**
 * @brief Checks if an IAT is hooked for current module (will soon be expanded to all modules)
 *
 * @return list of hooked iat entries
 *
 * @usage
 *  std::list<ProcessData::ImportFunction> hookedIATEntries = Integrity::FetchHookedIATEntries();
 */
std::list<ProcessData::ImportFunction> Integrity::FetchHookedIATEntries()
{
	bool isIATHooked = false;

	std::list<ProcessData::ImportFunction> hookedIATEntries;

	auto modules = Process::GetLoadedModules();

	if (modules.size() == 0)
	{
		throw std::runtime_error("Module size was 0!");
	}

	for (auto mod : modules)
	{
		std::list<ProcessData::ImportFunction> IATFunctions = Process::GetIATEntries(Utility::ConvertWStringToString(mod.baseName));

		for (const auto& IATEntry : IATFunctions)
		{
			DWORD moduleSize = Process::GetModuleSize(IATEntry.Module);

			bool FoundIATEntryInModule = false;

			if (moduleSize != 0)  //some IAT functions in k32 can point to ntdll (forwarding), thus we have to compare IAT to each other whitelisted DLL range
			{
				for (auto mod : modules)
				{
					uintptr_t LowAddr = (uintptr_t)mod.dllInfo.lpBaseOfDll;
					uintptr_t HighAddr = LowAddr + mod.dllInfo.SizeOfImage;

					if (IATEntry.FunctionPtr >= LowAddr && IATEntry.FunctionPtr < HighAddr) //each IAT entry needs to be checked thru all loaded ranges
					{
						FoundIATEntryInModule = true;
					}
				}

				if (!FoundIATEntryInModule) //iat points to outside loaded module
				{

					std::cout << "Hooked IAT detected: " << IATEntry.AssociatedModuleName.c_str() << " at: " << IATEntry.FunctionPtr << std::endl;

					hookedIATEntries.push_back(IATEntry);
				}
			}
			else //error, we shouldnt get here!
			{
				std::cerr << " Couldn't fetch  module size @ Detections::DoesIATContainHooked" << std::endl;
				return hookedIATEntries;
			}
		}
	}

	return hookedIATEntries;
}

/**
 * @brief Checks if an IAT is hooked for current module (will soon be expanded to all modules). Faster execution time than `FetchHookedIATEntries`
 *
 * @return True/False if any function ptr is hooked in the IAT of main module
 *
 * @usage
 *  bool isIATHooked = Integrity::DoesIATContainHooked();
 */
bool Integrity::DoesIATContainHooked()
{
	bool isIATHooked = false;

	auto modules = Process::GetLoadedModules();

	if (modules.size() == 0)
	{
		throw std::runtime_error("Module size was 0!");
	}

	for (auto mod : modules)
	{
		std::list<ProcessData::ImportFunction> IATFunctions = Process::GetIATEntries(Utility::ConvertWStringToString(mod.baseName));

		for (ProcessData::ImportFunction IATEntry : IATFunctions)
		{
			DWORD moduleSize = Process::GetModuleSize(IATEntry.Module);

			bool FoundIATEntryInModule = false;

			if (moduleSize != 0)  //some IAT functions in k32 can point to ntdll (forwarding), thus we have to compare IAT to each other whitelisted DLL range
			{
				for (auto mod : modules)
				{
					uintptr_t LowAddr = (uintptr_t)mod.dllInfo.lpBaseOfDll;
					uintptr_t HighAddr = LowAddr + mod.dllInfo.SizeOfImage;

					if (IATEntry.FunctionPtr >= LowAddr && IATEntry.FunctionPtr < HighAddr) //each IAT entry needs to be checked thru all loaded ranges
					{
						FoundIATEntryInModule = true;
					}
				}

				if (!FoundIATEntryInModule) //iat points to outside loaded module
				{
					std::cout << "Hooked IAT detected: " << IATEntry.AssociatedModuleName.c_str() << " at: " << IATEntry.FunctionPtr << std::endl;

					isIATHooked = true;
					break;
				}
			}
			else //error, we shouldnt get here!
			{
#if _LOGGING_ENABLED
				std::cerr << " Couldn't fetch  module size @ Detections::DoesIATContainHooked" << std::endl;
#endif
				continue;
			}
		}
	}

	return isIATHooked;
}

/**
 * @brief check if `address` falls within a known module (element of `modules`)
 * @param `modules`  list of modules to check for `address`
 * @param `address`  address to check
 *
 * @return true/false  if `address` falls within a known module (element of `modules`)
 */
bool Integrity::IsAddressInModule(__in const std::vector<ProcessData::MODULE_DATA>& modules, __in const uintptr_t address)
{
	for (const auto& module : modules)
	{
		if (address >= (uintptr_t)module.hModule && address < ((uintptr_t)module.hModule + module.dllInfo.SizeOfImage))
		{
			return true; // Address is within a known module
		}
	}
	return false;
}


/**
 * @brief Checks if the program's TLS callback has been modified
 * @details if TLS callbacks lead to somewhere outside our module, is might be modified, or another module installed their own 
 *
 * @return true/false  whether the TLS callbacks point to inside our main module or not
 *
 */
bool Integrity::IsTLSCallbackStructureModified() 
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

	if ((uintptr_t)tlsDir < (uintptr_t)MainModule || (uintptr_t)tlsDir > (uintptr_t)((uintptr_t)MainModule + ModuleSize)) //check if TLS directory address is inside main module for good measure
	{
		return true;
	}

	PIMAGE_TLS_CALLBACK* pTLSCallbacks = (PIMAGE_TLS_CALLBACK*)tlsDir->AddressOfCallBacks;

	int tlsCount = 0;

	for (int i = 0; pTLSCallbacks[i] != nullptr; i++) //traverse actual callback list, we are expecting (atleast) one callback in our program
	{
		if (!pTLSCallbacks)
			return true;

		if ((uintptr_t)pTLSCallbacks[i] < (uintptr_t)MainModule || (uintptr_t)pTLSCallbacks[i] > (uintptr_t)((uintptr_t)MainModule + ModuleSize)) //check if TLS callback is outside of main module range
		{
			return true;
		}

		tlsCount++;
	}

	if (tlsCount != 1) //last check to make sure there is atleast one TLS callback **note: you may have to modify this line if your protected program is using its own additional TLS callback**
		return true;  //an attacker may try to register their own additional TLS callback at runtime without changing the original one

	return false;
}

/**
 * @brief Checks if a blob of bytes looks like a typical PE header, based on positions of MZ & PE signatures
 *
 * @param `pMemory` The memory blob to check
 *
 * @return true/false  if `pMemory` looks like a PE header
 *
 * @details PE headers can be stripped/erased to increase evasion, in this case this won't catch them
 *
 */
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