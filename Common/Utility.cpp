//By AlSch092 @ github
#include "Utility.hpp"

char* Utility::GenerateRandomString(int length) //make sure to delete[] memory after
{
    if (length == 0)
        return NULL;

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

    char* randomString = new char[(length + 1) * sizeof(char)];

    srand(time(NULL));

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

    srand(time(NULL));

    for (int i = 0; i < length; ++i)
        randomString[i] = charset[rand() % (wcslen(charset) - 1)];

    randomString[length] = '\0';

    return randomString;
}

void Utility::str_to_lower(char* str) 
{
    while (*str) {
        *str = tolower((unsigned char)*str);
        str++;
    }
}

char* Utility::strstr_case_insensitive(const char* haystack, const char* needle) 
{
    if (!*needle) 
    {
        return (char*)haystack;
    }

    // Create lowercase copies of haystack and needle
    char* haystack_lower = _strdup(haystack);
    char* needle_lower = _strdup(needle);

    if (!haystack_lower || !needle_lower)
    {
        // Memory allocation failed
        return NULL;
    }

    // Convert both strings to lowercase
    str_to_lower(haystack_lower);
    str_to_lower(needle_lower);

    // Search for the needle in the haystack
    char* result = strstr(haystack_lower, needle_lower);

    // Clean up memory
    free(haystack_lower);
    free(needle_lower);

    // Return the result as a pointer to the original haystack
    if (result) {
        return (char*)(haystack + (result - haystack_lower));
    }
    else {
        return NULL;
    }
}

bool Utility::strcmp_insensitive(const char* s1, const char* s2)
{
    if (s1 == NULL || s2 == NULL)
        return false;

    int len1 = strlen(s1); //can overflow: be careful -> a process with a specific name could trigger an overflow situation
    int len2 = strlen(s2);

    if (len1 != len2) //strings can't be equal if lengths are diff
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

    int len1 = wcslen(s1); //can overflow: be careful
    int len2 = wcslen(s2);

    if (len1 != len2) //strings can't be equal if lengths are diff
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
    // Create a locale object with the system default locale
    std::locale loc("");

    // Create a codecvt facet for UTF-8 conversion
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;

    // Convert the wide string to a narrow string using UTF-8 encoding
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

void Utility::addUniqueString(std::list<std::string>&strList, const std::string & str)
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
            return false; // An element in list1 is not in list2
        }
    }
    return true; // All elements in list1 are in list2
}