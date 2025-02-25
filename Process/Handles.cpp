//By AlSch092 @github
#include "Handles.hpp"

/*
    GetHandles - Returns a vector of SYSTEM_HANDLE representing all running handles on the system
*/
std::vector<Handles::SYSTEM_HANDLE> Handles::GetHandles()
{
    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemHandleInfo = 16
    } SYSTEM_INFORMATION_CLASS;

    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");

	if (hNtDll == NULL)
	{
		Logger::logf(Err, "Failed to fetch ntdll module address @ IsMachineAllowingSelfSignedDrivers. Error code : % lu\n", GetLastError());
		return {};
	}

    NtQuerySystemInformationFunc NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hNtDll, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation)
    {
        Logger::logf(Err, "Could not get NtQuerySystemInformation function address @ Handles::GetHandles");
        return {};
    }

    ULONG bufferSize = 0x10000;
    PVOID buffer = nullptr;
    NTSTATUS status = 0;

    do 
    {
        buffer = malloc(bufferSize);

        if (!buffer) 
        {
            Logger::logf(Err, "Memory allocation failed @ Handles::GetHandles");
            return {};
        }

        status = NtQuerySystemInformation(SystemHandleInfo, buffer, bufferSize, &bufferSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH) 
        {
            free(buffer);
            bufferSize *= 2;
        }
        else if (!(((NTSTATUS)(status)) >= 0))
        {
            Logger::logf(Err, "NtQuerySystemInformation failed @ Handles::GetHandles");
            free(buffer);
            return {};
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;

    std::vector<SYSTEM_HANDLE> handles;

	for (int i = 0; i < handleInfo->HandleCount; i++)
	{
		if (handleInfo->Handles[i].ProcessId <= 4) //save some memory and cpu by skipping system process handles
		{
			continue;
		}

        //if (handleInfo->Handles[i].ObjectTypeNumber != 7) //optionally, also skip if its not a process handle (for example, obtained from OpenProcess). however we can't guarantee it will be 7 across diff windows versions
        //{
        //    continue;
        //}

		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		handles.push_back(handle);
	}

    free(buffer);
    return handles;
}

/*
    DetectOpenHandlesToProcess - returns a vector of SYSTEM_HANDLE which represent open handles in other processes to our current process
    Can be used to detect OpenProcess , a bit expensive on CPU though since all system handles must be enumerated
*/
std::vector<Handles::SYSTEM_HANDLE> Handles::DetectOpenHandlesToProcess()
{
    DWORD currentProcessId = GetCurrentProcessId();
    auto handles = GetHandles();
    std::vector<Handles::SYSTEM_HANDLE> handlesTous;

    for (auto& handle : handles)
    {
        if (handle.ProcessId != currentProcessId)
        {
            if (handle.ProcessId <= 4) //skip any system processes
            {
                continue;
            }

            HANDLE processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);

            if (processHandle) 
            {
                HANDLE duplicatedHandle = INVALID_HANDLE_VALUE;

                if (DuplicateHandle(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &duplicatedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
                {
                    if (GetProcessId(duplicatedHandle) == currentProcessId)
                    {
                        std::wstring procName = Process::GetProcessName(handle.ProcessId);
                        int size = sizeof(Handles::Whitelisted) / sizeof(UINT64);

                        bool foundWhitelisted = false;

                        for (int i = 0; i < size; i++)   // Check if handle belongs to whitelisted process; if so skip this handle
                        {
                            if (wcscmp(Handles::Whitelisted[i], procName.c_str()) == 0) //whitelisted program has open handle
                            {
                                foundWhitelisted = true;
                                break;
                            }
                        }

                        if (!foundWhitelisted)
                        {
                            Logger::logf(Detection, "Handle %d from process %d is referencing our process.", handle.Handle, handle.ProcessId);
                            handle.ReferencingOurProcess = true;
                            handlesTous.push_back(handle);
                        }
                    }
                    else
                    {
                        handle.ReferencingOurProcess = false;
                    }

                    if(duplicatedHandle != INVALID_HANDLE_VALUE)
                        CloseHandle(duplicatedHandle);
                }

                CloseHandle(processHandle);
            }
            else //possibly SYSTEM process, skip over
            {
                continue;
            }
        }
    }

    return handlesTous;
}

/*
    DoesProcessHaveOpenHandleTous - returns true if any handle in vector `handles`  points to our process
    Can be used to detect open process handles to our process from other processes
*/
bool Handles::DoesProcessHaveOpenHandleToUs(__in const DWORD pid, __in const std::vector <Handles::SYSTEM_HANDLE> handles)
{
    if (pid <= 4) //skip system-related processes
        return false;

    for (const auto& handle : handles)
    {
        if (handle.ProcessId == pid && handle.ReferencingOurProcess)
        {
            return true;
        }   
    }

    return false;
}
