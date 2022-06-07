#pragma once
#define EXCEPTION_EXECUTE_HANDLER       1
#define EXCEPTION_CONTINUE_SEARCH       0
#define EXCEPTION_CONTINUE_EXECUTION    -1
#include <stdint.h>

template <class T> //prevent needing to redefine on each line

class Utility
{
public:
	
	static T ReadPointer(uint64_t ulBase, uint64_t ulOffset)
	{
		__try
		{
			return *(T*)(*(uint64_t*)ulBase + ulOffset);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { return (T)NULL; }
	}

	static bool WritePointer(uint64_t ulBase, uint64_t ulOffset, T iValue)
	{
		__try { *(T*)(*(uint64_t*)ulBase + ulOffset) = iValue; return true; }
		__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
	}

	static T DereferenceSafe(uint64_t ulAddress)
	{
		__try
		{
			return *(T*)ulAddress;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { return (T)NULL; }
	}
};
