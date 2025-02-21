//By AlSch092 @ github
#pragma once
#include <stdint.h>
#include <Windows.h>
#include <time.h>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <list>
#include <algorithm> //std::transform
#include <locale>
#include <cwctype> //std::towlower

using namespace std;

/*
	Utility is a 'helper class' which provides some functions for string operations and comparisons
*/
class Utility final
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

	static string GenerateRandomString(__in const int length);
	static wstring GenerateRandomWString(__in const int length);

	static wstring ConvertStringToWString(__in const std::string& wstr);
	static string ConvertWStringToString(__in const std::wstring& wstr);

	static vector<string> splitStringBySpace(__in char* str);

	static void addUniqueString(__inout list<string>& strList, __in const string& str);
	static bool areAllElementsInList(__in const std::list<std::string>& list1, __in const std::list<std::string>& list2);

	static void str_to_lower(__inout char* str);
	static char* strstr_case_insensitive(__in const char* haystack, __in const char* needle);

	static wstring ToLower(__in const std::wstring& str);
	static bool ContainsWStringInsensitive(__in const std::wstring& haystack, __in const std::wstring& needle);
};