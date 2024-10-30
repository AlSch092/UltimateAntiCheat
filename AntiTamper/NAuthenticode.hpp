#pragma once
#include <tchar.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include "../Common/Logger.hpp"

#pragma comment (lib, "wintrust")

/*
	The `Authenticode` namespace contains functions to help with certificate & catalog verification
*/
namespace Authenticode
{
	BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);
	BOOL VerifyCatalogSignature(LPCWSTR filePath);
	BOOL HasSignature(LPCWSTR filePath);
}

