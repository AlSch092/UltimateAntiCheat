//By AlSch092 @ github
#pragma once
#include <stdint.h>
#include <Windows.h>
#include <time.h>
#include <string>
#include <vector>
#include <list>
#include <algorithm> //std::transform
#include <cwctype> //std::towlower

/*
	Utility is a 'helper class' which provides some functions for string operations and comparisons
*/
class Utility final
{
public:
	
	static bool strcmp_insensitive(__in const char* s1, __in const char* s2);
	static bool wcscmp_insensitive(__in const wchar_t* s1, __in const wchar_t* s2);

	static std::string GenerateRandomString(__in const int length);
	static std::wstring GenerateRandomWString(__in const int length);

	static std::wstring ConvertStringToWString(__in const std::string& wstr);
	static std::string ConvertWStringToString(__in const std::wstring& wstr);

	static std::vector<std::string> splitStringBySpace(__in char* str);

	static void addUniqueString(__inout std::list<std::string>& strList, __in const std::string& str);
	static bool areAllElementsInList(__in const std::list<std::string>& list1, __in const std::list<std::string>& list2);

	static void str_to_lower(__inout char* str);
	static char* strstr_case_insensitive(__in const char* haystack, __in const char* needle);

	static std::wstring ToLower(__in const std::wstring& str);
	static bool ContainsWStringInsensitive(__in const std::wstring& haystack, __in const std::wstring& needle);
};