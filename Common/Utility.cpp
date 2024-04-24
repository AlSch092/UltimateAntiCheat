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