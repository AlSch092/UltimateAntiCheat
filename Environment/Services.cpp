#include "Services.hpp"

BOOL Services::GetServiceModules()
{
    SC_HANDLE scmHandle = NULL, serviceHandle = NULL;
    DWORD bytesNeeded, servicesReturned, resumeHandle = 0;
    ENUM_SERVICE_STATUS_PROCESS* services;
    BOOL result;

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (scmHandle == NULL) 
    {
        printf("Failed to open Service Control Manager: %lu\n", GetLastError());
        return 1;
    }

    result = EnumServicesStatusEx( scmHandle, SC_ENUM_PROCESS_INFO,SERVICE_WIN32, SERVICE_STATE_ALL, NULL,0, &bytesNeeded,&servicesReturned,&resumeHandle,NULL);

    if (!result && GetLastError() != ERROR_MORE_DATA) 
    {
        printf("Failed to enumerate services (preliminary call): %lu\n", GetLastError());
        CloseServiceHandle(scmHandle);
        return 1;
    }

    services = (ENUM_SERVICE_STATUS_PROCESS*)malloc(bytesNeeded);
    
    if (services == NULL) 
    {
        printf("Memory allocation failed @ GetServiceModules\n");
        CloseServiceHandle(scmHandle);
        return 1;
    }

    result = EnumServicesStatusEx(scmHandle,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_STATE_ALL,(LPBYTE)services,bytesNeeded,&bytesNeeded,&servicesReturned,&resumeHandle,NULL);

    if (!result) 
    {
        printf("Failed to enumerate services: %lu\n", GetLastError());
        free(services);
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    for (DWORD i = 0; i < servicesReturned; i++) 
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

BOOL Services::GetLoadedDrivers()
{
    DWORD cbNeeded;
    HMODULE drivers[1024];
    DWORD numDrivers;

    if (!EnumDeviceDrivers((LPVOID*)drivers, sizeof(drivers), &cbNeeded)) 
    {
        printf("Failed to enumerate device drivers\n");
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
            printf("Failed to get driver information @ GetLoadedDrivers : error %d\n", GetLastError());
            return FALSE;
        }
    }

	return TRUE;
}

BOOL Services::IsDriverSigned(wstring driverPath) 
{
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = driverPath.c_str();

    WINTRUST_DATA trustData;
    memset(&trustData, 0, sizeof(trustData));
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = 0;
    trustData.hWVTStateData = NULL;
    trustData.pFile = &fileInfo;

    LONG lStatus = WinVerifyTrust(NULL, &guidAction, &trustData);

    if (lStatus != ERROR_SUCCESS)
    {
        //printf("WinVerifyTrust failed with error code %ld\n", lStatus);
        return FALSE;
    }

    return TRUE;
}

list<wstring> Services::GetUnsignedDrivers()
{
    list<wstring> unsignedDrivers;

    if (DriverPaths.size() == 0)
    {
        if (!GetLoadedDrivers())
        {
            printf("Failed to get driver list @ GetUnsignedDrivers : error %d\n", GetLastError());
            return unsignedDrivers;
        }
    }

    for (const std::wstring& driverPath : DriverPaths) 
    {
        if (!IsDriverSigned(driverPath))
        {
            //wprintf(L"[WARNING] Found unsigned or outdated certificate on driver: %s\n", driverPath.c_str());
            unsignedDrivers.push_back(driverPath);
        }
        else
        {
            wprintf(L"[INFO] Driver is signed: %s\n", driverPath.c_str());
        }
    }

    return unsignedDrivers;
}

//Opens BCDEdit.exe and pipes output to check if testsigning is enabled
BOOL Services::IsMachineAllowingSelfSignedDrivers()
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
        printf("[ERROR] Failed to retrieve Windows directory path @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        return FALSE;
    }

    CHAR volumeName[MAX_PATH];
    if (!GetVolumePathNameA(volumePath, volumeName, MAX_PATH)) 
    {
        printf("[ERROR] Failed to retrieve volume path name @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        return FALSE;
    }

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) //use a pipe to read output of bcdedit command
    {
        printf("[ERROR] CreatePipe failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
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
        printf("[ERROR] CreateProcess failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return foundTestsigning;
    }

    //..wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(hWritePipe);

    if (!ReadFile(hReadPipe, szOutput, 1024 - 1, &bytesRead, NULL)) //now read our pipe
    {
        printf("[ERROR] ReadFile failed @ Services::IsMachineAllowingSelfSignedDrivers: %d\n", GetLastError());
        CloseHandle(hReadPipe);
        return foundTestsigning;
    }

    szOutput[bytesRead] = '\0';

    if (strstr(szOutput, "testsigning             Yes") != NULL)  //this works on Windows 10, I can't guarantee it does on other versions of windows
    {
        foundTestsigning = TRUE;
    }
    else if (strstr(szOutput, "The boot configuration data store could not be opened") != NULL)
    {
        printf("[ERROR] Failed to run bcdedit @ IsMachineAllowingSelfSignedDrivers\n");
        foundTestsigning = FALSE;
    }
    else
    { 
        printf("Windows is in regular mode.\n");
        foundTestsigning = FALSE;
    }

    CloseHandle(hReadPipe);
    return foundTestsigning;
}