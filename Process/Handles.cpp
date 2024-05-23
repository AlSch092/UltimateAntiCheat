//By AlSch092 @github
#include "Handles.hpp"

/*
    GetHandles - Returns a vector of SYSTEM_HANDLE representing all running handles on the system
*/
std::vector<Handles::SYSTEM_HANDLE> Handles::GetHandles()
{
    NtQuerySystemInformationFunc NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Could not get NtQuerySystemInformation function address @ Handles::GetHandles");
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
            Logger::logf("UltimateAnticheat.log", Err, "Memory allocation failed @ Handles::GetHandles");
            return {};
        }

        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) 
        {
            free(buffer);
            bufferSize *= 2;
        }
        else if (!NT_SUCCESS(status))
        {
            Logger::logf("UltimateAnticheat.log", Err, "NtQuerySystemInformation failed @ Handles::GetHandles");
            free(buffer);
            return {};
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;
    std::vector<SYSTEM_HANDLE> handles(handleInfo->Handles, handleInfo->Handles + handleInfo->HandleCount);
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
            if (handle.ProcessId == 0 || handle.ProcessId == 4)
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
                        Logger::logf("UltimateAnticheat.log", Detection, "Handle %d from process %d is referencing our process.", handle.Handle, handle.ProcessId);
                        handle.ReferencingOurProcess = true;
                        handlesTous.push_back(handle);
                    }
                    else
                    {
                        handle.ReferencingOurProcess = false;
                    }

                    CloseHandle(duplicatedHandle);
                }
                CloseHandle(processHandle);
            }
            else
            {
                //Logger::logf("UltimateAnticheat.log", Warning, "Couldn't open process with id %d @ Handles::DetectOpenHandlesToProcess (possible LOCAL SERVICE or SYSTEM process)", handle.ProcessId);
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
bool Handles::DoesProcessHaveOpenHandleTous(DWORD pid, std::vector <Handles::SYSTEM_HANDLE> handles)
{
    if (pid == 0 || pid == 4) //system idle process + system pids
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