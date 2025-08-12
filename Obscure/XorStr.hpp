#pragma once
#include <cstddef>

constexpr char XorKey = 0x55;

constexpr char encrypt_char(char c, char key, int index) 
{
    return c ^ (key + index);
}

constexpr char decrypt_char(char c, char key, int index)
{
    return c ^ (key + index);
}

constexpr char encrypt_wchar(wchar_t c, wchar_t key, int index)
{
    return c ^ (key + index);
}

constexpr char decrypt_wchar(wchar_t c, wchar_t key, int index)
{
    return c ^ (key + index);
}


/**
 * @brief A constexpr encrypted string class that uses XOR encryption for compile-time obfuscation.
 *
 * @param N The size of the string, including the null terminator.
 */
template <std::size_t N>
class EncryptedString 
{
private:
    char encrypted[N];

public:

    /**
     * @brief encrypts `str` and places it into the class object's `encrypted` array.
     * @details Should not be called directly - use the make_encrypted function instead
     * @param `str` text to be encrypted
     * @return EncryptedString object
    */
    constexpr EncryptedString(const char(&str)[N]) : encrypted{} 
    {
        for (std::size_t i = 0; i < N; ++i) 
        {
            encrypted[i] = encrypt_char(str[i], XorKey, i);
        }
    }

    /**
	 * @brief decrypts a `EncryptedString` object that was created with `make_encrypted` and places the decrypted output into the provided buffer.
     *
     * @param `output` location where decrypted output should be placed
     * @return void
    */
    void decrypt(char* output) const 
    {
        for (std::size_t i = 0; i < N; ++i) 
        {
            output[i] = decrypt_char(encrypted[i], XorKey, i);
        }
    }

    /**
     * @brief decrypts a `EncryptedString` object that was created with `make_encrypted` and returns the decrypted output
     *
	 * @return std::string decrypted output string
    */
    std::string decrypt() const
    {
        std::string output(N, '\0');
        for (std::size_t i = 0; i < N; ++i)
        {
            output[i] = decrypt_char(encrypted[i], XorKey, i);
        }
        return output;
    }

    constexpr int getSize() const { return N; }
};

/**
 * @brief Creates an `EncryptedString` object from a string literal.
 *
 * @param `str`  string literal to be encrypted
 * @param `N` size of the string literal, including the null terminator
 * @return EncryptedStringW object containing an encrypted version of the string
*/
template <std::size_t N>
constexpr EncryptedString<N> make_encrypted(const char(&str)[N]) 
{
    return EncryptedString<N>(str);
}

template <std::size_t N>
class EncryptedStringW
{
private:
    wchar_t encrypted[N];

public:

    /**
	 * @brief encrypts `str` and places it into the class object's `encrypted` array.
     * @details Should not be called directly - use the make_encrypted function instead
	 * @param `str` wide text string to be encrypted
     * @return EncryptedStringW object
    */
    constexpr EncryptedStringW(const wchar_t(&str)[N]) : encrypted{}
    {
        for (std::size_t i = 0; i < N; ++i)
        {
            encrypted[i] = encrypt_wchar(str[i], XorKey, i);
        }
    }

    /**
     * @brief decrypts a `EncryptedString` object that was created with `make_encrypted` and places the decrypted output into the provided buffer.
     *
     * @param `output` location where decrypted output should be placed
     * @return void
    */
    void decrypt(wchar_t* output) const
    {
        for (std::size_t i = 0; i < N; ++i)
        {
            output[i] = decrypt_wchar(encrypted[i], XorKey, i);
        }
    }

    /**
     * @brief decrypts a `EncryptedString` object that was created with `make_encrypted` and returns the decrypted output
     *
     * @return std::wstring decrypted output string
    */
    std::wstring decrypt() const
    {
        std::wstring output(N, L'\0');
        for (std::size_t i = 0; i < N; ++i)
        {
            output[i] = decrypt_wchar(encrypted[i], XorKey, i);
        }
        return output;
    }

    constexpr int getSize() const { return N; }
};

/**
 * @brief Creates an `EncryptedStringW` object from a wide string literal.
 *
 * @param `str` wide string literal to be encrypted
 * @param `N` size of the string literal, including the null terminator
 * @return EncryptedStringW object containing an encrypted version of the string
*/
template <std::size_t N>
constexpr EncryptedStringW<N> make_encrypted(const wchar_t(&str)[N])
{
    return EncryptedStringW<N>(str);
}