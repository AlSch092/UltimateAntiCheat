#pragma once
#include <cstddef>

constexpr char XOR_KEY = 0x55;

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

//compile-time string obfuscation using template recursion, making use of constexpr to allow for cleaner code (XOR strings don't need to be declared as array of chars)
template <std::size_t N>
class EncryptedString 
{
private:
    char encrypted[N];

public:
    constexpr EncryptedString(const char(&str)[N]) : encrypted{} 
    {
        for (std::size_t i = 0; i < N; ++i) 
        {
            encrypted[i] = encrypt_char(str[i], XOR_KEY, i);
        }
    }

    //runtime decryption
    void decrypt(char* output) const 
    {
        for (std::size_t i = 0; i < N; ++i) 
        {
            output[i] = decrypt_char(encrypted[i], XOR_KEY, i);
        }
    }

    constexpr int getSize() const { return N; }
};

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

    constexpr EncryptedStringW(const wchar_t(&str)[N]) : encrypted{}
    {
        for (std::size_t i = 0; i < N; ++i)
        {
            encrypted[i] = encrypt_wchar(str[i], XOR_KEY, i);
        }
    }

    void decrypt(wchar_t* output) const
    {
        for (std::size_t i = 0; i < N; ++i)
        {
            output[i] = decrypt_wchar(encrypted[i], XOR_KEY, i);
        }
    }

    constexpr int getSize() const { return N; }
};

template <std::size_t N>
constexpr EncryptedStringW<N> make_encrypted(const wchar_t(&str)[N])
{
    return EncryptedStringW<N>(str);
}