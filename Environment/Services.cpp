//By AlSch092 @ Github
#include "Services.hpp"

#ifdef _MSC_VER
#include <intrin.h>  // For __cpuid on MSVC (Microsoft Compiler)
#endif

/*
    FetchBlacklistedDrivers - read internet page at `url`, parse each line of the response to add to our blacklisted driver list
    returns `false` on failure
*/
bool Services::FetchBlacklistedDrivers(__in const char* url)
{
    if (url == nullptr)
        return false;

    HttpRequest request;
    request.url = url;
    request.cookie = "";
    request.body = "";
    request.requestHeaders =
    {
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Accept: text/plain, */*; q=0.01",
        "Accept-Language: en-US,en;q=0.5",
        "Connection: keep-alive"
    };

    if (!HttpClient::GetRequest(request))
    {
        return false;
    }

    stringstream ss(request.responseText);

    string blacklistedDriver;

    while (getline(ss, blacklistedDriver))
    {
        if (!blacklistedDriver.empty() && blacklistedDriver.back() == '\r')
        {
            blacklistedDriver.pop_back();
        }

        wstring s = Utility::ConvertStringToWString(blacklistedDriver);
        BlacklistedDrivers.push_back(s);
    }
    
    return true;
}

/*
    GetServiceModules - Fills the `DriverPaths` class member variable with a list of drivers loaded on the system
    returns TRUE if the function succeeded
*/
BOOL Services::GetServiceModules()
{
    SC_HANDLE scmHandle = NULL, serviceHandle = NULL;
    DWORD bytesNeeded, servicesReturned, resumeHandle = 0;
    ENUM_SERVICE_STATUS_PROCESS* services;
    BOOL result;

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (scmHandle == NULL) 
    {
        Logger::logf(Err, "Failed to open Service Control Manager @ GetServiceModules: %lu\n", GetLastError());
        return FALSE;
    }

    result = EnumServicesStatusEx( scmHandle, SC_ENUM_PROCESS_INFO,SERVICE_WIN32, SERVICE_STATE_ALL, NULL,0, &bytesNeeded,&servicesReturned,&resumeHandle,NULL);

    if (!result && GetLastError() != ERROR_MORE_DATA) 
    {
        Logger::logf(Err, "Failed to enumerate services @ GetServiceModules: %lu\n", GetLastError());
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    services = (ENUM_SERVICE_STATUS_PROCESS*)malloc(bytesNeeded);
    
    if (services == NULL) 
    {
        Logger::logf(Err, "Memory allocation failed @ GetServiceModules");
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    result = EnumServicesStatusEx(scmHandle,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,(LPBYTE)services,bytesNeeded,&bytesNeeded,&servicesReturned,&resumeHandle,NULL);

    if (!result) 
    {
        Logger::logf(Err, "Failed to enumerate services @ GetServiceModules: %lu\n", GetLastError());
        free(services);
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    for (DWORD i = 0; i < servicesReturned; i++)  //iterate services and add to our managed list
    {
        Service* service = new Service();
        service->pid = services[i].ServiceStatusProcess.dwProcessId;
        service->displayName = services[i].lpDisplayName;
        service->serviceName = services[i].lpServiceName;

        switch (services[i].ServiceStatusProcess.dwCurrentState) 
        {
            case SERVICE_STOPPED:
                service->isRunning = false;
                break;
            case SERVICE_RUNNING:                
                service->isRunning = true;
                break;
            case SERVICE_PAUSED:
                service->isRunning = false;
                break;
            default:
                break;
        }

        ServiceList.push_back(service);
    }

    free(services);
    CloseServiceHandle(scmHandle);

	return TRUE;
}

/*
    GetLoadedDrivers - Fills the `DriverPaths` class member variable with a list of drivers loaded on the system
    returns TRUE if the function succeeded
*/
BOOL Services::GetLoadedDrivers()
{
    DWORD cbNeeded;
    HMODULE drivers[1024];
    DWORD numDrivers;

    if (!EnumDeviceDrivers((LPVOID*)drivers, sizeof(drivers), &cbNeeded)) 
    {
        Logger::logf(Err, "Failed to enumerate device drivers @ GetLoadedDrivers");
        return FALSE;
    }

    numDrivers = cbNeeded / sizeof(HMODULE);

    for (DWORD i = 0; i < numDrivers; i++) 
    {
        TCHAR driverName[MAX_PATH];
        TCHAR driverPath[MAX_PATH];

        if (GetDeviceDriverBaseName(drivers[i], driverName, MAX_PATH) && GetDeviceDriverFileName(drivers[i], driverPath, MAX_PATH))
        {
            this->DriverPaths.push_back(driverPath);

            for (wstring blacklisted : this->BlacklistedDrivers) //enumerate blacklisted drivers, check if driverPath contains a blacklisted driver
            {
                if (Utility::ContainsWStringInsensitive(driverPath, blacklisted))
                {
                    Logger::logfw(Detection, L"Found Vulnerable loaded driver @ GetLoadedDrivers: %s", driverPath);
                    this->FoundBlacklistedDrivers.push_back(driverPath);
                }
            }
        }
        else 
        {
            Logger::logf(Err, "Failed to get driver information @ GetLoadedDrivers : error %d\n", GetLastError());
            return FALSE;
        }
    }

	return TRUE;
}

/*
    GetUnsignedDrivers - returns a list of unsigned driver names (wstring) loaded on the machine
*/
list<wstring> Services::GetUnsignedDrivers()
{
    list<wstring> unsignedDrivers;

    if (DriverPaths.size() == 0)
    {
        if (!GetLoadedDrivers())
        {
            Logger::logf(Err, "Failed to get driver list @ GetUnsignedDrivers : error %d\n", GetLastError());
            return unsignedDrivers;
        }
    }

    const wstring windowsDrive = Services::GetWindowsDriveW();

    for (const std::wstring& driverPath : DriverPaths)
    {
        wstring fixedDriverPath;
        bool foundWhitelisted = false;

        if (driverPath.find(L"\\SystemRoot\\", 0) != wstring::npos) /* replace "\\SystemRoot\\" with "\\??\\<windowsVolume>\\WINDOWS" */
        {
            fixedDriverPath = L"\\??\\" + windowsDrive + L"WINDOWS\\" + driverPath.substr(12);
        }
        else
        {
            fixedDriverPath = driverPath;
        }

        for (const wstring& whitelisted : WhitelistedUnsignedDrivers)
        {
            if (Utility::wcscmp_insensitive(whitelisted.c_str(), driverPath.c_str()) )
            {
                foundWhitelisted = true;
                break;
            }
        }

        if (!foundWhitelisted && !Authenticode::HasSignature(fixedDriverPath.c_str(), TRUE))
        {
            Logger::logfw(Warning, L"Found unsigned or outdated certificate on driver: %s\n", fixedDriverPath.c_str());
            unsignedDrivers.push_back(fixedDriverPath);
        }
        //else
        //{
        //    Logger::logfw(Info, L"Driver is signed: %s\n", fixedDriverPath.c_str()); //commented out to prevent flooding the console & log file
        //}
    }

    return unsignedDrivers;
}

/*
    GetUnsignedDrivers - returns a list of unsigned driver names (wstring) loaded on the machine
*/
list<wstring> Services::GetUnsignedDrivers(__in list<wstring>& cachedVerifiedDriverList)
{
    list<wstring> unsignedDrivers;

    if (DriverPaths.size() == 0)
    {
        if (!GetLoadedDrivers())
        {
            Logger::logf(Err, "Failed to get driver list @ GetUnsignedDrivers : error %d\n", GetLastError());
            return unsignedDrivers;
        }
    }

    const wstring windowsDrive = Services::GetWindowsDriveW();

    for (const std::wstring& driverPath : DriverPaths) //enumerate all loaded drivers
    {
        wstring fixedDriverPath;

        bool foundWhitelisted = false;

        if (driverPath.find(L"\\SystemRoot\\", 0) != wstring::npos) /* replace "\\SystemRoot\\" with "\\??\\<windowsVolume>\\WINDOWS" */
        {
            fixedDriverPath = L"\\??\\" + windowsDrive + L"WINDOWS\\" + driverPath.substr(12);
        }
        else
        {
            fixedDriverPath = driverPath;
        }

        for (const wstring& whitelisted : WhitelistedUnsignedDrivers) //check against whitelisted unsigned list, if so we can skip the cert check
        {
            if (Utility::wcscmp_insensitive(whitelisted.c_str(), driverPath.c_str()))
            {
                foundWhitelisted = true;
                break;
            }
        }

        for (const wstring& cached : cachedVerifiedDriverList) //check against cached/already verified list, if so we can skip the cert check
        {
            if (Utility::wcscmp_insensitive(cached.c_str(), driverPath.c_str()))
            {
                foundWhitelisted = true;
                break;
            }
        }

        if (!foundWhitelisted && !Authenticode::HasSignature(fixedDriverPath.c_str(), TRUE))
        {
            Logger::logfw(Warning, L"Found unsigned or outdated certificate on driver: %s\n", fixedDriverPath.c_str());
            unsignedDrivers.push_back(fixedDriverPath);
        }
        else
        {
            //Logger::logfw(Info, L"Driver is signed: %s\n", fixedDriverPath.c_str()); //commented out to prevent flooding the console & log file

            if (find(cachedVerifiedDriverList.begin(), cachedVerifiedDriverList.end(), fixedDriverPath) == cachedVerifiedDriverList.end()) //signed driver not found in cache, so add it
            {
                cachedVerifiedDriverList.push_back(fixedDriverPath); //add to list if not already on it
            }
        }
    }

    return unsignedDrivers;
}

/*
    IsMachineAllowingSelfSignedDrivers - uses NtQuerySystemInformationFunc to check if bit in CodeIntegrityOptions is set (CODEINTEGRITY_OPTION_TESTSIGN structure)
    returns TRUE if test signing mode was found.
*/
BOOL Services::IsTestsigningEnabled()
{
    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemCodeIntegrity = 103
    } SYSTEM_INFORMATION_CLASS;

    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
    {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    } SYSTEM_CODEINTEGRITY_INFORMATION;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    if (ntdll == NULL)
    {
        Logger::logf(Err, "Failed to fetch ntdll module address @ IsMachineAllowingSelfSignedDrivers. Error code : % lu\n", GetLastError());
        return FALSE;
    }

    NtQuerySystemInformationFunc NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(ntdll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation)
    {
        Logger::logf(Err, "Could not get NtQuerySystemInformation function address @ Handles::GetHandles");
        return {};
    }

    SYSTEM_CODEINTEGRITY_INFORMATION sci = { sizeof(sci), 0 };

    ULONG flags = 0;
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemCodeIntegrity, &sci, sizeof(sci), NULL);

    if (status == 0)
    {
        return (sci.CodeIntegrityOptions & 0x02); //CODEINTEGRITY_OPTION_TESTSIGN
    }

    return FALSE;
}

/*
    IsDebugModeEnabled - checks registry for system start option to check if debug mode is enabled
    returns TRUE if debug  mode is enabled.
*/
BOOL Services::IsDebugModeEnabled()
{
    HKEY hKey;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwValue = 0;
    const char* registryPath = "SYSTEM\\CurrentControlSet\\Control";
    const char* valueName = "SystemStartOptions";
    wchar_t buffer[256];
    DWORD bufferSize = sizeof(buffer);
    DWORD type = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    bool isDebug = false;

    if (RegQueryValueExA(hKey, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&buffer), &bufferSize) == ERROR_SUCCESS)
    {
        if (type == REG_SZ)
        {
            std::wstring options(buffer);
            std::transform(options.begin(), options.end(), options.begin(), ::towlower);
            isDebug = options.find(L"debug") != std::wstring::npos;
        }
    }

    RegCloseKey(hKey);
    return isDebug;
}

/*
    IsSecureBootEnabled - checks if secure bool is enabled on machine through a powershell cmdlet (`Confirm-SecureBootUEFI`)
    returns `true` if secure boot is enabled
*/
BOOL Services::IsSecureBootEnabled()
{
    HKEY hKey;
    LONG lResult;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwValue = 0;
    const char* registryPath = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State";
    const char* valueName = "UEFISecureBootEnabled";

    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        Logger::logf(Err, "Error opening registry key:  (%d) @ Services::IsSecureBootEnabled", GetLastError());
        return FALSE;
    }

    lResult = RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)&dwValue, &dwSize);

    if (lResult != ERROR_SUCCESS)
    {
        Logger::logf(Err, "Error querying registry value: %d @ Services::IsSecureBootEnabled", GetLastError());
        RegCloseKey(hKey);
        return FALSE;
    }

    RegCloseKey(hKey);
    return dwValue;
}

/*
    GetWindowsDrive - return drive where windows is installed, such as C:\\
*/
string Services::GetWindowsDrive()
{
    CHAR volumePath[MAX_PATH];
    DWORD charCount;

    charCount = GetWindowsDirectoryA(volumePath, MAX_PATH);
    if (charCount == 0)
    {
        Logger::logf(Err, "Failed to retrieve Windows directory path @ Services::GetWindowsPath: %d\n", GetLastError());
        return "";
    }

    CHAR volumeName[MAX_PATH];
    if (!GetVolumePathNameA(volumePath, volumeName, MAX_PATH))
    {
        Logger::logf(Err, "Failed to retrieve volume path name @ Services::GetWindowsPath: %d\n", GetLastError());
        return "";
    }

    return volumeName;
}

/*
    GetWindowsDriveW - return drive where windows is installed, such as C:\\
*/
wstring Services::GetWindowsDriveW()
{
    wchar_t volumePath[MAX_PATH];
    DWORD charCount;

    charCount = GetWindowsDirectoryW(volumePath, MAX_PATH);
    if (charCount == 0)
    {
        Logger::logf(Err, "Failed to retrieve Windows directory path @ Services::GetWindowsPathW: %d\n", GetLastError());
        return L"";
    }

    wchar_t volumeName[MAX_PATH];
    if (!GetVolumePathNameW(volumePath, volumeName, MAX_PATH))
    {
        Logger::logf(Err, "Failed to retrieve volume path name @ Services::GetWindowsPathW: %d\n", GetLastError());
        return L"";
    }

    return volumeName;
}

/*
    IsRunningAsAdmin - returns TRUE if the application is running as administrator context
*/
BOOL Services::IsRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) 
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

/*
    GetHardwareDevicesW - returns a list<DeviceW>  representing various devices on the machine
*/
list<DeviceW> Services::GetHardwareDevicesW()
{
    list<DeviceW> deviceList;

    HDEVINFO deviceInfoSet;
    SP_DEVINFO_DATA deviceInfoData;
    DWORD deviceIndex = 0;

    deviceInfoSet = SetupDiGetClassDevsA(NULL, "PCI", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);     //Get the list of all PCI devices

    if (deviceInfoSet == INVALID_HANDLE_VALUE) 
    {
        Logger::logf(Warning, "SetupDiGetClassDevs failed with error: %d @ Services::GetHardwareDevicesW", GetLastError());
        return {};
    }

    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    while (SetupDiEnumDeviceInfo(deviceInfoSet, deviceIndex, &deviceInfoData)) 
    {
        deviceIndex++;
        DeviceW d;

        TCHAR deviceInstanceId[MAX_DEVICE_ID_LEN];
        if (CM_Get_Device_ID(deviceInfoData.DevInst, deviceInstanceId, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS)         // Get the device instance ID
        {
            d.InstanceID = wstring(deviceInstanceId);
        }
        else
        {
            continue;
        }

        TCHAR deviceDescription[1024];
        if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, &deviceInfoData, SPDRP_DEVICEDESC, NULL, (PBYTE)deviceDescription, sizeof(deviceDescription), NULL))          // Get the device description
        {
            d.Description = wstring(deviceDescription);
        }
        else 
        {
            continue;
        }

        Logger::logfw(Info, L"Found Device: %s\n", d.Description.c_str());
        deviceList.push_back(d);
    }

    if (GetLastError() != ERROR_NO_MORE_ITEMS)
    {
        Logger::logf(Warning, "SetupDiEnumDeviceInfo failed with error: %d @ Services::GetHardwareDevicesW", GetLastError());
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet); 

    return deviceList;
}

/*
       CheckUSBDevices - returns TRUE if any hardware in the PCIe slot are blacklisted (DMA involved)
*/
BOOL Services::CheckUSBDevices()
{
    HDEVINFO deviceInfoSet;
    SP_DEVINFO_DATA deviceInfoData;
    DWORD i;
    TCHAR deviceID[MAX_PATH];

    BOOL foundFTDI = FALSE;
    BOOL foundLeonardo = FALSE;

    deviceInfoSet = SetupDiGetClassDevs(NULL, TEXT("USB"), NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);

    if (deviceInfoSet == INVALID_HANDLE_VALUE) 
    {
        //Logger::log(Err, "Failed to get device information set.");
        return FALSE;
    }

    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) 
    {
        if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, &deviceInfoData, SPDRP_HARDWAREID, NULL, (PBYTE)deviceID, sizeof(deviceID), NULL)) 
        {       
            if (_tcsstr(deviceID, TEXT("VID_0403")) && _tcsstr(deviceID, TEXT("PID_6010")))  //Check for FTDI FT601 in the device ID
            {
                foundFTDI = TRUE;
            }

            if (_tcsstr(deviceID, TEXT("VID_0403")) && _tcsstr(deviceID, TEXT("PID_6000")))  //Check for FTDI FT600 in the device ID
            {
                foundFTDI = TRUE;
            }

            if (_tcsstr(deviceID, TEXT("VID_2341")) && _tcsstr(deviceID, TEXT("PID_8036")))  //Check for Arduino Leonardo
            {
                foundLeonardo = TRUE;
            }
        }
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);

    return (foundFTDI | foundLeonardo);
}

/*
    WindowsVersions GetWindowsVersion() - returns current machine version
*/
WindowsVersion Services::GetWindowsVersion()
{
    RTL_OSVERSIONINFOW osVersionInfo;
    osVersionInfo.dwOSVersionInfoSize = sizeof(osVersionInfo);

    NTSTATUS status = RtlGetVersion(&osVersionInfo);

    if (status != 0)
    {
        Logger::logf(Warning, "Services::GetWindowsMajorVersion failed with error: %x");
        return ErrorUnknown;
    }

    if (osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 0)
    {
        return Windows2000;
    }
    else if (osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 1)
    {
        return WindowsXP;
    }
    else if (osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 2)
    {
        return WindowsXPProfessionalx64;
    }
    else if (osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 0)
    {
        return WindowsVista;
    }
    else if (osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 1)
    {
        return Windows7;
    }
    else if (osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 2)
    {
        return Windows8;
    }
    else if (osVersionInfo.dwMajorVersion == 10 && osVersionInfo.dwMinorVersion == 0)
    {
        if (osVersionInfo.dwBuildNumber < 21996)
        {
            return Windows10;
        }
        else
        {
            return Windows11;
        }
    }

    return ErrorUnknown;
}

/*
    Services::IsHypervisor - returns true if a hypervisor is detected by using the __cpuid intrinsic function
    the 31st bit of ECX indicates a hypervisor
*/
bool Services::IsHypervisorPresent()
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;     // bit 31 of ECX = 1 means a hypervisor is present
}

/*
    Services::GetCPUVendor - fetches the CPU vendor
Additionally, 0x40000001 to 0x400000FF can be queries in the 2nd parameter to __cpuid for more hypervisor-specific info
*/
string Services::GetCPUVendor() 
{
    int cpuInfo[4] = { 0 };

    __cpuid(cpuInfo, 0);

    char vendor[13] = { 0 };

    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);

    return string(vendor);
}

/*
  GetHypervisorVendor - check vendor of hypervisor, if present
  Common results:
"Microsoft Hv"	Hyper-V
"KVMKVMKVM"	KVM
"VMwareVMware"	VMware
"XenVMMXenVMM"	Xen
"prl hyperv"	Parallels
"VBoxVBoxVBox"	VirtualBox
*/
string Services::GetHypervisorVendor()
{
    int cpuInfo[4] = { 0 };

    __cpuid(cpuInfo, 0x40000000);

    char vendor[13] = { 0 };

    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);

    return string(vendor);
}

/*
    Services::LoadDriver - register a service and load a driver given a driverName and driverPath using SCM
    return `true` on success
*/
bool Services::LoadDriver(__in const std::wstring& serviceName, __in const std::wstring& driverPath)
{
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

    bool loadSuccess = true;

    if (!hSCManager)
    {
        Logger::logfw(Warning, L"Failed to open SCM: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = CreateService(      //create driver service
        hSCManager,
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_START | DELETE | SERVICE_STOP,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hService)
    {
        if (GetLastError() == ERROR_SERVICE_EXISTS)
        {
            hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_START);
        }
        else
        {
            Logger::logfw(Warning, L"Failed to create service:  %d", GetLastError());
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    if (!StartService(hService, 0, nullptr))     // Start the driver
    {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        {
            Logger::logfw(Warning, L"Failed to start service: %d", GetLastError());
            loadSuccess = false;
        }
    }

    if(loadSuccess)
        Logger::logfw(Info, L"Driver %s loaded successfully.", serviceName.c_str());

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return loadSuccess;
}

/*
    Services::UnloadDriver - unregister the driver service and unload a driver given a driverName and driverPath using SCM
    return `true` on success
*/
bool Services::UnloadDriver(__in const std::wstring& serviceName)
{
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);

    bool unloadSuccess = true;

    if (!hSCManager)
    {
        Logger::logfw(Warning, L"Failed to open SCM: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_STOP | DELETE);

    if (!hService)
    {
        Logger::logfw(Warning, L"Failed to open driver service: %d", GetLastError());
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS status;

    if (ControlService(hService, SERVICE_CONTROL_STOP, &status))     //stop driver
    {
        Logger::logfw(Info, L"Driver stopped successfully.");
    }
    else if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
    {
        Logger::logfw(Warning, L"Failed to stop driver service: %d", GetLastError()); //don't return false yet incase the service was already stopped, in that case delete it
        unloadSuccess = false;
    }

    if (!DeleteService(hService))     //delete service
    {
        Logger::logfw(Warning, L"Failed to delete driver service: %d", GetLastError());
        unloadSuccess = false;
    }

    if(unloadSuccess)
        Logger::logfw(Info, L"Driver %s unloaded successfully.", serviceName.c_str());

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return unloadSuccess;
}


/*
    EnumerateProcesses - return list of running processes ids
*/
std::list<DWORD> Services::EnumerateProcesses()
{
    std::list<DWORD> procs;

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            procs.push_back(entry.th32ProcessID);
        }
    }

    CloseHandle(snapshot);
    return procs;
}

/*
    GetProcessDirectoryW - return directory of process `pid`
*/
std::string Services::GetProcessDirectory(__in const DWORD pid)
{
    if (pid <= 4)
        return "";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == NULL)
    {
        Logger::logf(Err, "Failed to open process with PID %d @ GetProcessDirectory", pid);
        return "";
    }

    char imagePath[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameA(hProcess, 0, imagePath, &size))
    {
        char* lastSlash = strrchr(imagePath, '\\');
        if (lastSlash != nullptr)
        {
            *lastSlash = '\0';
            CloseHandle(hProcess);
	    strcat(imagePath, "\\");
            return std::string(imagePath);
        }
        else
        {
            Logger::logf(Err, "Failed to find directory in the image path (pid %d) @ GetProcessDirectory", pid);
        }
    }
    else
    {
        Logger::logf(Err, "Failed to query process image name with pid %d @ GetProcessDirectory", pid);
    }

    CloseHandle(hProcess);
    return "";
}

/*
    GetProcessDirectoryW - return directory of process `pid`
*/
std::wstring Services::GetProcessDirectoryW(__in const DWORD pid)
{
    if (pid <= 4)
        return L"";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == nullptr)
    {
        Logger::logf(Err, "Failed to open process with PID %d @ GetProcessDirectory", pid);
        return L"";
    }

    wchar_t imagePath[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, imagePath, &size))
    {
        wchar_t* lastSlash = wcsrchr(imagePath, L'\\'); //get last occurance of \\ as a ptr

        if (lastSlash != nullptr)
        {
            *lastSlash = '\0'; //__try,__except won't compile here, function requires unwinding

            CloseHandle(hProcess);
            wcscat(imagePath, L"\\");
            return std::wstring(imagePath);
        }
        else
        {
            Logger::logf(Err, "Failed to find directory in the image path (pid %d) @ GetProcessDirectory", pid);
        }
    }
    else
    {
        Logger::logf(Err, "Failed to query process image name with pid %d @ GetProcessDirectory", pid);
    }


    CloseHandle(hProcess);
    return L"";
}

bool Services::IsDriverRunning(__in const std::wstring& serviceName)
{
    if (serviceName.size() == 0)
        return false;

    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);

    if (!hSCManager)
    {
        Logger::logfw(Warning, L"Failed to open SCM: %d", GetLastError());
        return false;
    }

    //open driver service
    SC_HANDLE hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_QUERY_STATUS);

    if (!hService)
    {
        Logger::logfw(Info, L"Failed to open service %s: %d (this is not an error)", serviceName.c_str(), GetLastError());
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS status;

    if (!QueryServiceStatus(hService, &status))     //query the service status
    {
        Logger::logfw(Warning, L"Failed to query service status: %d", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return (status.dwCurrentState == SERVICE_RUNNING);
}