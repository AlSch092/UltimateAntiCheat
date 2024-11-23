//By AlSch092 @ github
#include "Utility.hpp"

char* Utility::GenerateRandomString(int length) //make sure to delete[] memory after
{
    if (length == 0)
        return NULL;

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

    char* randomString = new char[(length + 1) * sizeof(char)];

    srand(time((time_t*)NULL));

    for (int i = 0; i < length; ++i)
        randomString[i] = charset[rand() % (strlen(charset) - 1)];

    randomString[length] = '\0';

    return randomString;
}

wchar_t* Utility::GenerateRandomWString(int length) //make sure to delete[] memory after
{
    if (length == 0)
        return NULL;

    const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

    wchar_t* randomString = new wchar_t[(length + 1) * sizeof(wchar_t)];

    srand(time((time_t*)NULL));

    for (int i = 0; i < length; ++i)
        randomString[i] = charset[rand() % (wcslen(charset) - 1)];

    randomString[length] = '\0';

    return randomString;
}

void Utility::str_to_lower(char* str)
{
    while (*str)
    {
        *str = tolower((unsigned char)*str);
        str++;
    }
}

char* Utility::strstr_case_insensitive(const char* haystack, const char* needle)
{
    if (!haystack || !needle)
    {
        return nullptr;
    }

    if (!*needle)
    {
        return (char*)haystack;
    }

    char* haystack_lower = _strdup(haystack);
    char* needle_lower = _strdup(needle);

    if (!haystack_lower || !needle_lower)
    {
        free(haystack_lower);
        free(needle_lower);
        return nullptr;
    }

    for (char* p = haystack_lower; *p; ++p)
    {
        *p = std::tolower(*p);
    }

    for (char* p = needle_lower; *p; ++p)
    {
        *p = std::tolower(*p);
    }

    char* result = strstr(haystack_lower, needle_lower);
    char* final_result = result ? (char*)(haystack + (result - haystack_lower)) : nullptr;
    free(haystack_lower);
    free(needle_lower);

    return final_result;
}

bool Utility::strcmp_insensitive(const char* s1, const char* s2)
{
    if (s1 == NULL || s2 == NULL)
        return false;

    int len1 = (int)strlen(s1);
    int len2 = (int)strlen(s2);

    if (len1 != len2)
        return false;

    for (int i = 0; i < len1; i++)
    {
        if (tolower(s1[i]) != tolower(s2[i]))
        {
            return false;
        }
    }

    return true;
}

bool Utility::wcscmp_insensitive(const wchar_t* s1, const wchar_t* s2)
{
    if (s1 == NULL || s2 == NULL)
        return false;

    int len1 = (int)wcslen(s1);
    int len2 = (int)wcslen(s2);

    if (len1 != len2)
        return false;

    for (int i = 0; i < len1; i++)
    {
        if (towlower(s1[i]) != towlower(s2[i]))
        {
            return false;
        }
    }

    return true;
}

std::string Utility::ConvertWStringToString(const std::wstring& wstr)
{
    std::locale loc("");
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(wstr);
}

std::wstring Utility::ConvertStringToWString(const std::string& str)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

std::vector<std::string> Utility::splitStringBySpace(char* str)
{
    std::vector<std::string> result;
    char* token = strtok(str, " ");
    while (token != nullptr)
    {
        result.push_back(std::string(token));
        token = strtok(nullptr, " ");
    }
    return result;
}

void Utility::addUniqueString(std::list<std::string>& strList, const std::string& str)
{
    if (find(strList.begin(), strList.end(), str) == strList.end())
    {
        strList.push_back(str);
    }
}

bool Utility::areAllElementsInList(const std::list<std::string>& list1, const std::list<std::string>& list2)
{
    for (const auto& str : list1)
    {
        if (std::find(list2.begin(), list2.end(), str) == list2.end())
        {
            return false; //an element in list1 is not in list2
        }
    }
    return true; //elements in list1 are in list2
}

std::wstring Utility::ToLower(const std::wstring& str) 
{
    std::wstring lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
        [](wchar_t ch) { return std::towlower(ch); });
    return lowerStr;
}

bool Utility::ContainsWStringInsensitive(const std::wstring& haystack, const std::wstring& needle) 
{
    std::wstring lowerHaystack = ToLower(haystack);
    std::wstring lowerNeedle = ToLower(needle); //convert both strings to lowercase, check if the needle is in the haystack
    return lowerHaystack.find(lowerNeedle) != std::wstring::npos;
}