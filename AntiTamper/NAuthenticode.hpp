#pragma once
#include <tchar.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include "../Logger.hpp"

#pragma comment (lib, "wintrust")

#define CATROOT_PATH L"Windows\\System32\\CatRoot" //needs prefix of correct windows-located drive
#define CATROOT2_PATH L"Windows\\System32\\CatRoot2" //needs prefix of correct windows-located drive
#define DRIVERSTORE_PATH L"Windows\\System32\\DriverStore\\FileRepository"

namespace Authenticode
{
	BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);
}

