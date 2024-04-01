#include "Utility.hpp"

bool Utility::strcmp_insensitive(const char* s1, const char* s2)
{
    if (s1 == NULL || s2 == NULL)
        return -1;

    int len1 = strlen(s1); //can overflow: be careful
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
        return -1;

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
