//By AlSch092 @ Github
#include "Services.hpp"

#ifdef _MSC_VER
#include <intrin.h>  // For __cpuid on MSVC (Microsoft Compiler)
#endif

/*
    FetchBlacklistedDrivers - read internet page at `url`, parse each line of the response to add to our blacklisted driver list
    returns `false` on failure
*/
bool Services::FetchBlacklistedDrivers(const char* url)
{
    if (url == nullptr)
        return false;

    HttpClient* h = new HttpClient();
    vector<string> responseHeaders;
    string response = h->ReadWebPage(BlacklistedDriversRepository, {}, "", responseHeaders); //fetch blacklisted drivers
    delete h;

    if (response.size() == 0)
        return false;

    stringstream ss(response);

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
        Logger::logf("UltimateAnticheat.log", Err, "Failed to open Service Control Manager @ GetServiceModules: %lu\n", GetLastError());
        return FALSE;
    }

    result = EnumServicesStatusEx( scmHandle, SC_ENUM_PROCESS_INFO,SERVICE_WIN32, SERVICE_STATE_ALL, NULL,0, &bytesNeeded,&servicesReturned,&resumeHandle,NULL);

    if (!result && GetLastError() != ERROR_MORE_DATA) 
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to enumerate services @ GetServiceModules: %lu\n", GetLastError());
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    services = (ENUM_SERVICE_STATUS_PROCESS*)malloc(bytesNeeded);
    
    if (services == NULL) 
    {
        Logger::logf("UltimateAnticheat.log", Err, "Memory allocation failed @ GetServiceModules");
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    result = EnumServicesStatusEx(scmHandle,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,(LPBYTE)services,bytesNeeded,&bytesNeeded,&servicesReturned,&resumeHandle,NULL);

    if (!result) 
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to enumerate services @ GetServiceModules: %lu\n", GetLastError());
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
        Logger::logf("UltimateAnticheat.log", Err, "Failed to enumerate device drivers @ GetLoadedDrivers");
        return FALSE;
    }

    numDrivers = cbNeeded / sizeof(HMODULE);

    for (DWORD i = 0; i < numDrivers; i++) 
    {
        TCHAR driverName[MAX_PATH];
        TCHAR driverPath[MAX_PATH];

        if (GetDeviceDriverBaseName(drivers[i], driverName, MAX_PATH) && GetDeviceDriverFileName(drivers[i], driverPath, MAX_PATH))
        {
            DriverPaths.push_back(driverPath);

            for (wstring blacklisted : this->BlacklistedDrivers) //enumerate blacklisted drivers, check if driverPath contains a blacklisted driver
            {
                if (Utility::ContainsWStringInsensitive(driverPath, blacklisted))
                {
                    Logger::logfw("UltimateAnticheat.log", Detection, L"Found Vulnerable loaded driver @ GetLoadedDrivers: %s", driverPath);
                    this->FoundBlacklistedDrivers.push_back(driverPath);
                }
            }
        }
        else 
        {
            Logger::logf("UltimateAnticheat.log", Err, "Failed to get driver information @ GetLoadedDrivers : error %d\n", GetLastError());
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
            Logger::logf("UltimateAnticheat.log", Err, "Failed to get driver list @ GetUnsignedDrivers : error %d\n", GetLastError());
            return unsignedDrivers;
        }
    }

    const wstring windowsDrive = Services::GetWindowsDriveW();

    for (const std::wstring& driverPath : DriverPaths)
    {
        wstring fixedDriverPath;
        bool foundWhitelisted = false;

        if (driverPath.find(L"\\SystemRoot\\", 0) != wstring::npos)
        {
            fixedDriverPath = L"\\??\\" + windowsDrive + L"WINDOWS\\" + driverPath.substr(12);
        }
        else
        {
            fixedDriverPath = driverPath;
        }

        for (const wstring& whitelisted : WhitelistedUnsignedDrivers) //std::find won't work well here because of possible case sensitivity differences
        {
            if (Utility::wcscmp_insensitive(whitelisted.c_str(), driverPath.c_str()))
            {
                foundWhitelisted = true;
                break;
            }
        }

        if (!foundWhitelisted && !Authenticode::HasSignature(fixedDriverPath.c_str()))
        {
            Logger::logfw("UltimateAnticheat.log", Warning, L"Found unsigned or outdated certificate on driver: %s\n", fixedDriverPath.c_str());
            unsignedDrivers.push_back(fixedDriverPath);
        }
        //else
        //{
        //    Logger::logfw("UltimateAnticheat.log", Info, L"Driver is signed: %s\n", fixedDriverPath.c_str()); //commented out to prevent flooding the console
        //}
    }

    return unsignedDrivers;
}

/*
    IsMachineAllowingSelfSignedDrivers - Opens BCDEdit.exe and pipes output to check if testsigning is enabled. May require running program as administrator.
    returns TRUE if test signing mode was found.
*/
BOOL Services::IsTestsigningEnabled()
{
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char szOutput[1024];
    DWORD bytesRead;
    BOOL foundTestsigning = FALSE;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    string volumeName = GetWindowsDrive();

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) //use a pipe to read output of bcdedit command
    {
        Logger::logf("UltimateAnticheat.log", Err, "CreatePipe failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        return foundTestsigning;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;

    string bcdedit_location = "Windows\\System32\\bcdedit.exe";
    string fullpath_bcdedit = (volumeName.c_str() + bcdedit_location);

    if (!CreateProcessA(fullpath_bcdedit.c_str(), NULL, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CreateProcess failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    //..wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(hWritePipe);
    CloseHandle(pi.hThread);

    if (!ReadFile(hReadPipe, szOutput, 1024 - 1, &bytesRead, NULL)) //now read our pipe
    {
        Logger::logf("UltimateAnticheat.log", Err, "ReadFile failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        return FALSE;
    }

    CloseHandle(hReadPipe);

    szOutput[bytesRead] = '\0';

    if (strstr(szOutput, "The boot configuration data store could not be opened") != NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to run bcdedit @ IsMachineAllowingSelfSignedDrivers. Please make sure program is run as administrator\n");
        foundTestsigning = FALSE;
    }

    char* token = strtok(szOutput, "\r\n");

    while (token != NULL)      //Iterate through tokens
    {
        if (strstr(token, "testsigning") != NULL && strstr(token, "Yes") != NULL)
        {
            foundTestsigning = TRUE;
        }

        token = strtok(NULL, "\r\n");
    }

    return foundTestsigning;
}


/*
    IsDebugModeEnabled - Opens BCDEdit.exe and pipes output to check if debug mode is enabled. May require running program as administrator.
    returns TRUE if debug  mode is enabled.
*/
BOOL Services::IsDebugModeEnabled()
{
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char szOutput[1024];
    DWORD bytesRead;
    BOOL foundKDebugMode = FALSE;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    string volumeName = GetWindowsDrive();

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) //use a pipe to read output of bcdedit command
    {
        Logger::logf("UltimateAnticheat.log", Err, "CreatePipe failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        return foundKDebugMode;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;

    string bcdedit_location = "Windows\\System32\\bcdedit.exe";
    string fullpath_bcdedit = (volumeName + bcdedit_location);

    if (!CreateProcessA(fullpath_bcdedit.c_str(), NULL, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CreateProcess failed @ Services::IsDebugModeEnabled: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return foundKDebugMode;
    }

    //..wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(hWritePipe);
    CloseHandle(pi.hThread);

    if (!ReadFile(hReadPipe, szOutput, 1024 - 1, &bytesRead, NULL)) //now read our pipe
    {
        Logger::logf("UltimateAnticheat.log", Err, "ReadFile failed @ Services::IsDebugModeEnabled: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        return foundKDebugMode;
    }

    CloseHandle(hReadPipe);

    szOutput[bytesRead] = '\0';

    if (strstr(szOutput, "The boot configuration data store could not be opened") != NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to run bcdedit @ IsMachineAllowingSelfSignedDrivers. Please make sure program is run as administrator\n");
        foundKDebugMode = FALSE;
    }

    char* token = strtok(szOutput, "\r\n"); //split based on new line

    while (token != NULL)      //Iterate through tokens, both "yes" and "debug" on same line = debug mode
    {
        if (strstr(token, "debug") != NULL && strstr(token, "Yes") != NULL)
        {
            foundKDebugMode = TRUE;
        }

        token = strtok(NULL, "\r\n");
    }

    return foundKDebugMode;
}

/*
    IsSecureBootEnabled - checks if secure bool is enabled on machine
*/
BOOL Services::IsSecureBootEnabled()
{
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char szOutput[1024];
    DWORD bytesRead;
    BOOL secureBootEnabled = FALSE;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) //use a pipe to read output of bcdedit command
    {
        Logger::logf("UltimateAnticheat.log", Err, "CreatePipe failed @ Services::IsSecureBootEnabled: %d\n", GetLastError());
        return FALSE;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;

    if (!CreateProcessA(NULL, (LPSTR)"powershell -c \"Confirm-SecureBootUEFI\"", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CreateProcess failed @ Services::IsSecureBootEnabled: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    //..wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(hWritePipe);
    CloseHandle(pi.hThread);

    if (!ReadFile(hReadPipe, szOutput, 1024 - 1, &bytesRead, NULL)) //now read our pipe
    {
        Logger::logf("UltimateAnticheat.log", Err, "ReadFile failed @ Services::IsSecureBootEnabled: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        return FALSE;
    }

    CloseHandle(hReadPipe);

    szOutput[bytesRead] = '\0';

    if (strstr(szOutput, "Cmdlet not supported on this platform") != NULL) //
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to run bcdedit @ IsMachineAllowingSelfSignedDrivers. Please make sure program is run as administrator\n");
        secureBootEnabled = FALSE;
    }

    if (strstr(szOutput, "False") != NULL)
    {
        secureBootEnabled = FALSE;
    }
    else if (strcmp(szOutput, "True") != NULL)
    {
        secureBootEnabled = TRUE;
    }

    return secureBootEnabled;
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
        Logger::logf("UltimateAnticheat.log", Err, "Failed to retrieve Windows directory path @ Services::GetWindowsPath: %d\n", GetLastError());
        return "";
    }

    CHAR volumeName[MAX_PATH];
    if (!GetVolumePathNameA(volumePath, volumeName, MAX_PATH))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to retrieve volume path name @ Services::GetWindowsPath: %d\n", GetLastError());
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
        Logger::logf("UltimateAnticheat.log", Err, "Failed to retrieve Windows directory path @ Services::GetWindowsPathW: %d\n", GetLastError());
        return L"";
    }

    wchar_t volumeName[MAX_PATH];
    if (!GetVolumePathNameW(volumePath, volumeName, MAX_PATH))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to retrieve volume path name @ Services::GetWindowsPathW: %d\n", GetLastError());
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
        Logger::logf("UltimateAnticheat.log", Warning, "SetupDiGetClassDevs failed with error: %d @ Services::GetHardwareDevicesW\n", GetLastError());
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

        Logger::logfw("UltimateAnticheat.log", Info, L"Found Device: %s\n", d.Description.c_str());
        deviceList.push_back(d);
    }

    if (GetLastError() != ERROR_NO_MORE_ITEMS)
    {
        Logger::logf("UltimateAnticheat.log", Warning, "SetupDiEnumDeviceInfo failed with error: %d @ Services::GetHardwareDevicesW\n", GetLastError());
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet); 

    return deviceList;
}

/*
    Services::IsSecureBootEnabled_RegKey - another method for checking secure boot without using a powershell process
*/
BOOL Services::IsSecureBootEnabled_RegKey()
{
    HKEY hKey;
    LONG lResult;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwValue = 0;
    const char* registryPath = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"; //optionally xor this
    const char* valueName = "UEFISecureBootEnabled";

    lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS) 
    {
        return FALSE;
    }

    lResult = RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)&dwValue, &dwSize);

    if (lResult != ERROR_SUCCESS) 
    {
        Logger::logf("UltimateAnticheat.log", Warning, "RegCloseKey failed with error: %d @ Services::IsSecureBootEnabled_RegKey\n", lResult);
        RegCloseKey(hKey);
        return FALSE;
    }

    if (dwValue == 1) 
    {
        RegCloseKey(hKey);
        return TRUE;
    }
    else 
    {
        RegCloseKey(hKey);
        return FALSE;
    }
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
        //Logger::log("UltimateAnticheat.log", Err, "Failed to get device information set.");
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
        Logger::logf("UltimateAnticheat.log", Warning, "Services::GetWindowsMajorVersion failed with error: %x", status);
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
        if (osVersionInfo.dwBuildNumber < 22000)
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
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);

    return string(vendor);
}

/*
    Services::LoadDriver - register a service and load a driver given a driverName and driverPath using SCM
    return `true` on success
*/
bool Services::LoadDriver(const std::wstring& driverName, const std::wstring& driverPath)
{
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

    bool loadSuccess = true;

    if (!hSCManager)
    {
        Logger::logfw("UltimateAnticheat.log", Warning, L"Failed to open SCM: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = CreateService(      //create driver service
        hSCManager,
        driverName.c_str(),
        driverName.c_str(),
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
            hService = OpenService(hSCManager, driverName.c_str(), SERVICE_START);
        }
        else
        {
            Logger::logfw("UltimateAnticheat.log", Warning, L"Failed to create service:  %d", GetLastError());
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    if (!StartService(hService, 0, nullptr))     // Start the driver
    {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        {
            Logger::logfw("UltimateAnticheat.log", Warning, L"Failed to start service: %d", GetLastError());
            loadSuccess = false;
        }
    }

    if(loadSuccess)
        Logger::logfw("UltimateAnticheat.log", Info, L"Driver %s loaded successfully.", driverName.c_str());

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return loadSuccess;
}

/*
    Services::UnloadDriver - unregister the driver service and unload a driver given a driverName and driverPath using SCM
    return `true` on success
*/
bool Services::UnloadDriver(const std::wstring& driverName)
{
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);

    bool unloadSuccess = true;

    if (!hSCManager)
    {
        Logger::logfw("UltimateAnticheat.log", Warning, L"Failed to open SCM: %d", GetLastError());
        return false;
    }

    SC_HANDLE hService = OpenService(hSCManager, driverName.c_str(), SERVICE_STOP | DELETE);

    if (!hService)
    {
        Logger::logfw("UltimateAnticheat.log", Warning, L"Failed to open driver service: %d", GetLastError());
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS status;

    if (ControlService(hService, SERVICE_CONTROL_STOP, &status))     //stop driver
    {
        Logger::logfw("UltimateAnticheat.log", Info, L"Driver stopped successfully.");
    }
    else if (GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
    {
        Logger::logfw("UltimateAnticheat.log", Warning, L"Failed to stop driver service: %d", GetLastError()); //don't return false yet incase the service was already stopped, in that case delete it
        unloadSuccess = false;
    }

    if (!DeleteService(hService))     //delete service
    {
        Logger::logfw("UltimateAnticheat.log", Warning, L"Failed to delete driver service: %d", GetLastError());
        unloadSuccess = false;
    }

    if(unloadSuccess)
        Logger::logfw("UltimateAnticheat.log", Info, L"Driver %s unloaded successfully.", driverName.c_str());

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return unloadSuccess;
}


/*
    EnumerateProcesses - return list of running processes ids
*/
list<DWORD> Services::EnumerateProcesses()
{
    list<DWORD> procs;

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
std::string Services::GetProcessDirectory(DWORD pid)
{
    if (pid <= 4)
        return "";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to open process with PID %d @ GetProcessDirectory", pid);
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
            Logger::logf("UltimateAnticheat.log", Err, "Failed to find directory in the image path (pid %d) @ GetProcessDirectory", pid);
        }
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to query process image name with pid %d @ GetProcessDirectory", pid);
    }

    CloseHandle(hProcess);
    return "";
}

/*
    GetProcessDirectoryW - return directory of process `pid`
*/
wstring Services::GetProcessDirectoryW(DWORD pid)
{
    if (pid <= 4)
        return L"";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to open process with PID %d @ GetProcessDirectory", pid);
        return L"";
    }

    wchar_t imagePath[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, imagePath, &size))
    {
        wchar_t* lastSlash = wcsrchr(imagePath, L'\\'); //get last occurance of \\ as a ptr

        if (lastSlash != nullptr)
        {
            *lastSlash = '\0';

            CloseHandle(hProcess);
            wcscat(imagePath, L"\\");
            return std::wstring(imagePath);
        }
        else
        {
            Logger::logf("UltimateAnticheat.log", Err, "Failed to find directory in the image path (pid %d) @ GetProcessDirectory", pid);
        }
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to query process image name with pid %d @ GetProcessDirectory", pid);
    }


    CloseHandle(hProcess);
    return L"";
}
