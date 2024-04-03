//By AlSch092 @ github
#pragma once
#include <stdint.h>
#include <Windows.h>
#include <time.h>

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

	static bool strcmp_insensitive(const char* s1, const char* s2);
	static bool wcscmp_insensitive(const wchar_t* s1, const wchar_t* s2);

	static char* GenerateRandomString(int length);
	static wchar_t* GenerateRandomWString(int length);
};