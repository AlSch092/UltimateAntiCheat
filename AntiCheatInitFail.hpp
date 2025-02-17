#pragma once
#include <string>
#include <exception>
#include <map>

enum AntiCheatInitFailReason
{
    NullSettings, BadAlloc, DriverNotFound, DriverUnsigned, DriverLoadFail, DispatchFail, NotAdministrator, NoSecureBoot, TestSigningEnabled, HypervisorPresent
};

class AntiCheatInitFail : public std::exception
{
    public:
		AntiCheatInitFailReason reasonEnum;

		AntiCheatInitFail(AntiCheatInitFailReason reason) : reasonEnum(reason) {}

		const char * what () const throw()
		{
			return reasonExplainMap.at(reasonEnum).c_str();
		}

	private:
	#ifdef _DEBUG
		const std::map<AntiCheatInitFailReason, const std::string> reasonExplainMap =
		{
			{ NullSettings, "Settings pointer was NULL" },
			{ BadAlloc, "Critical allocation failure" },
			{ DriverNotFound, "Could not  get absolute path from driver relative path" },
			{ DriverUnsigned, "Driver certificate subject/signer was not correct" },
			{ DriverLoadFail, "Could not load driver" },
			{ DispatchFail, "API::Dispatch failed" },
			{ NotAdministrator, "Program must be running as administrator in order to proceed, or change `bRequireRunAsAdministrator` to false." },
			{ NoSecureBoot, "Secure boot is not enabled, you cannot proceed. Please enable secure boot in your BIOS or change `bEnforceSecureBoot` to false." },
			{ TestSigningEnabled, "Test signing was enabled, you cannot proceed. Please turn off test signing via `bcdedit.exe`, or change `bEnforceDSE` to false." },
			{ HypervisorPresent, "Hypervisor was present with unknown/non-standard vendor." }
		};
	#else
	const std::map<AntiCheatInitFailReason, const std::string> reasonExplainMap =
	{
			{ NullSettings, "" },
			{ BadAlloc, "" },
			{ DriverNotFound, "" },
			{ DriverUnsigned, "" },
			{ DriverLoadFail, "" },
			{ DispatchFail, "" },
			{ NotAdministrator, "" },
			{ NoSecureBoot, "" },
			{ TestSigningEnabled, "" },
			{ HypervisorPresent, "" }

    };
	#endif
};
