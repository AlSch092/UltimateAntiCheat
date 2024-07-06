#include "Services.hpp"

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
    GetUnsignedDrivers - returns a list of unsigned driver names loaded on the machine
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

    for (const std::wstring& driverPath : DriverPaths) 
    {
        if (!Authenticode::HasSignature(driverPath.c_str()))
        {
            Logger::logfw("UltimateAnticheat.log", Warning, L"Found unsigned or outdated certificate on driver: %s\n", driverPath.c_str());
            unsignedDrivers.push_back(driverPath);
        }
        else
        {
            Logger::logfw("UltimateAnticheat.log", Info, L"Driver is signed: %s\n", driverPath.c_str());
        }
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

    CHAR volumePath[MAX_PATH];
    DWORD charCount;

    charCount = GetWindowsDirectoryA(volumePath, MAX_PATH);
    if (charCount == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to retrieve Windows directory path @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        return FALSE;
    }

    CHAR volumeName[MAX_PATH];
    if (!GetVolumePathNameA(volumePath, volumeName, MAX_PATH))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to retrieve volume path name @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        return FALSE;
    }

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
    string fullpath_bcdedit = (volumeName + bcdedit_location);

    if (!CreateProcessA(fullpath_bcdedit.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CreateProcess failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return FALSE;
    }

    //..wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(hWritePipe);

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

    CHAR volumePath[MAX_PATH];
    DWORD charCount;

    charCount = GetWindowsDirectoryA(volumePath, MAX_PATH);
    if (charCount == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to retrieve Windows directory path @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        return FALSE;
    }

    CHAR volumeName[MAX_PATH];
    if (!GetVolumePathNameA(volumePath, volumeName, MAX_PATH))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to retrieve volume path name @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        return FALSE;
    }

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

    if (!CreateProcessA(fullpath_bcdedit.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CreateProcess failed @ Services::IsDebugModeEnabled: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return foundKDebugMode;
    }

    //..wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(hWritePipe);

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

    char* token = strtok(szOutput, "\r\n");

    while (token != NULL)      //Iterate through tokens
    {
        if (strstr(token, "debug") != NULL && strstr(token, "Yes") != NULL)
        {
            foundKDebugMode = TRUE;
        }

        token = strtok(NULL, "\r\n");
    }

    return foundKDebugMode;
}