#pragma once
#include <stdint.h>
#include <Windows.h>

//pointer utilities -> reading and writing pointers and dereferencing 'safely'
class Utility
{
public:
	
	template<class T>
	static T ReadPointer(uint64_t ulBase, uint64_t ulOffset)
	{
		__try
		{
			return *(T*)(*(uint64_t*)ulBase + ulOffset);
		}
		__except (1) { return (T)NULL; }
	}

	template<class T>
	static bool WritePointer(uint64_t ulBase, uint64_t ulOffset, T iValue)
	{
		__try { *(T*)(*(uint64_t*)ulBase + ulOffset) = iValue; return true; }
		__except (1) { return false; }
	}

	template<class T>
	static T DereferenceSafe(uint64_t ulAddress)
	{
		__try
		{
			return *(T*)ulAddress;
		}
		__except (1) { return (T)NULL; }
	}
};
