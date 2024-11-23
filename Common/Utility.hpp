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

	static char* GenerateRandomString(int length);
	static wchar_t* GenerateRandomWString(int length);

	static wstring ConvertStringToWString(const std::string& wstr);
	static string ConvertWStringToString(const std::wstring& wstr);

	static vector<string> splitStringBySpace(char* str);

	static void addUniqueString(list<string>& strList, const string& str);
	static bool areAllElementsInList(const std::list<std::string>& list1, const std::list<std::string>& list2);

	static void str_to_lower(char* str);
	static char* strstr_case_insensitive(const char* haystack, const char* needle);

	static wstring ToLower(const std::wstring& str);
	static bool ContainsWStringInsensitive(const std::wstring& haystack, const std::wstring& needle);
};