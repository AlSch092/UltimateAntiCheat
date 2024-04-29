/*
	Exports.hpp - a part of the UltimateAntiCheat project
*/

#pragma once
#include <string>
#include <Windows.h>
#include <winternl.h>
#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp")
#include "../Logger.hpp"

using namespace std;

namespace Exports
{
	bool ChangeFunctionName(string dllName, string functionName, string newName); //modifies the image export directory -> writes over symbol names such that calls to GetProcAddress(symbol) will no longer hold valid. Can be used in different contexts to achieve anti-cheat goals, such as anti-dll injection and debugging
}