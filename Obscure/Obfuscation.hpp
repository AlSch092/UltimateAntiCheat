//By AlSch092 @ Github
#pragma once
#include <random>
#include <string>
#include <iostream>
#include <Windows.h>

#define OBFUSCATE_SEED 174440041
#define CONST_OPERATION_SEED 76543

using namespace std;

namespace Obfuscator //from my other project, ObfuscateThis !
{
	template <class T>
	__forceinline void obfuscate(T& data)
	{
		data = (data ^ OBFUSCATE_SEED) + CONST_OPERATION_SEED;
	}

	template <class T>
	__forceinline T deobfuscate(T& data)
	{
		return (data - CONST_OPERATION_SEED) ^ OBFUSCATE_SEED;
	}

	template <class T>
	__forceinline void obfuscate_with_key(T& data, int key)
	{
		hash<int> hasher;
		size_t hash_value = hasher(key);
		mt19937 rng(hash_value);

		uniform_int_distribution<int> distribution(1, INT_MAX);
		int random_number = distribution(rng);

		data = (data ^ OBFUSCATE_SEED) + random_number;
	}

	template <class T>
	__forceinline T deobfuscate_with_key(T& data, int key)
	{
		hash<int> hasher;
		size_t hash_value = hasher(key);
		mt19937 rng(hash_value);

		uniform_int_distribution<int> distribution(1, INT_MAX);
		int random_number = distribution(rng);

		return (data - random_number) ^ OBFUSCATE_SEED;
	}

	__forceinline void obfuscate_string(char* input, int maxStrLen)
	{
		if (input == NULL) return;

		int len = (int)strnlen_s(input, maxStrLen);

		for (int i = 0; i < len; i++)
		{
			if (i % 2 == 0) //destroys chances of someone brute forcing XOR key - alternating digits having a different operation
				input[i] = (input[i] ^ OBFUSCATE_SEED) + CONST_OPERATION_SEED;
			else
				input[i] = (input[i] ^ OBFUSCATE_SEED) - CONST_OPERATION_SEED;
		}
	}

	__forceinline string get_deobfuscated_string(char* input, int maxStrLen)
	{
		if (input == NULL) return "";

		size_t len = strnlen_s(input, maxStrLen);

		string deobfs;

		for (int i = 0; i < (int)len; i++)
		{
			if (i % 2 == 0)
			{
				char deobfs_ch = (input[i] - CONST_OPERATION_SEED) ^ OBFUSCATE_SEED;
				deobfs.push_back(deobfs_ch);
			}
			else
			{
				char deobfs_ch = (input[i] + CONST_OPERATION_SEED) ^ OBFUSCATE_SEED;
				deobfs.push_back(deobfs_ch);
			}
		}

		return deobfs;
	}
}

template<class T>
class ObfuscatedData
{
private:
	T someData; //data member to protect in memory

public:

	ObfuscatedData(T val)
	{
		SetData(val);
	}

	__forceinline T GetData()
	{
		return Obfuscator::deobfuscate(someData);
	}

	__forceinline void SetData(T value)
	{
		this->someData = value;
		Obfuscator::obfuscate(this->someData);
	}

	__forceinline T GetData(int key)
	{
		return Obfuscator::deobfuscate_with_key(someData, key);
	}

	__forceinline void SetData(T value, int key)
	{
		this->someData = value;
		Obfuscator::obfuscate_with_key(this->someData, key);
	}
};