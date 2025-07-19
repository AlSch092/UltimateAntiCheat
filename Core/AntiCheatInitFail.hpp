#pragma once
#include <string>
#include <exception>
#include <map>

enum AntiCheatInitFailReason
{
    NullSettings, BadAlloc, DriverNotFound, DriverUnsigned, DriverLoadFail, DispatchFail, PreInitializeChecksDidNotPass
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
			{ PreInitializeChecksDidNotPass, "One or more pre-initialize checks did not pass"}
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
			{ PreInitializeChecksDidNotPass, ""}
    };
	#endif
};
